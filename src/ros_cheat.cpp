// ROS Legacy — Runtime Memory Scanner Cheat
// No hardcoded offsets — scans /proc/self/mem dynamically
// Android ARM64, NDK C++17
// Inject: add libcheat.so to lib/arm64-v8a/, add loadLibrary("cheat") in smali

#include <jni.h>
#include <android/log.h>
#include <EGL/egl.h>
#include <GLES3/gl3.h>
#include <dlfcn.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <dirent.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <string>
#include <vector>
#include <atomic>
#include <mutex>
#include <thread>
#include <algorithm>

#include "imgui.h"
#include "imgui_impl_android.h"
#include "imgui_impl_opengl3.h"
#include "dobby.h"

#define TAG "ROS_CHEAT"
#define LOG(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)

// ─── MEMORY REGION ───────────────────────────────────────────────────────────

struct MemRegion {
    uintptr_t start, end;
    bool readable, writable;
};

static std::vector<MemRegion> g_regions;
static std::mutex g_region_mutex;

void RefreshRegions() {
    std::lock_guard<std::mutex> lk(g_region_mutex);
    g_regions.clear();
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        uintptr_t s, e; char perms[8];
        if (sscanf(line, "%lx-%lx %4s", &s, &e, perms) != 3) continue;
        // skip non-heap/anon regions that are too small
        if ((e - s) < 4) continue;
        bool r = perms[0] == 'r';
        bool w = perms[1] == 'w';
        if (!r) continue;
        // skip vdso/vsyscall/stack
        if (strstr(line, "[vdso]") || strstr(line, "[stack]") ||
            strstr(line, "[vsyscall]")) continue;
        g_regions.push_back({s, e, r, w});
    }
    fclose(f);
}

// Fixed: use /proc/self/mem fd (process_vm_readv not in NDK headers)
static int g_mem_fd = -1;

bool SafeRead(uintptr_t addr, void* out, size_t sz) {
    if (g_mem_fd < 0) {
        g_mem_fd = open("/proc/self/mem", O_RDONLY);
        if (g_mem_fd < 0) return false;
    }
    return pread64(g_mem_fd, out, sz, (off64_t)addr) == (ssize_t)sz;
}

bool SafeWrite(uintptr_t addr, const void* in, size_t sz) {
    // try direct write first (writable region)
    memcpy((void*)addr, in, sz);
    return true;
}

template<typename T>
T RMem(uintptr_t addr) { T v{}; SafeRead(addr, &v, sizeof(T)); return v; }

template<typename T>
void WMem(uintptr_t addr, T val) { SafeWrite(addr, &val, sizeof(T)); }

// ─── PATTERN / VALUE SCANNER ─────────────────────────────────────────────────

struct ScanResult {
    uintptr_t addr;
    float     val;
};

// Scan all readable regions for a float value within tolerance
std::vector<ScanResult> ScanFloat(float target, float tol = 0.5f) {
    std::vector<ScanResult> results;
    RefreshRegions();
    std::lock_guard<std::mutex> lk(g_region_mutex);
    for (auto& r : g_regions) {
        if ((r.end - r.start) > 64 * 1024 * 1024) continue; // skip huge regions
        size_t sz = r.end - r.start;
        std::vector<uint8_t> buf(sz);
        if (!SafeRead(r.start, buf.data(), sz)) continue;
        for (size_t i = 0; i + 4 <= sz; i += 4) {
            float v; memcpy(&v, buf.data() + i, 4);
            if (std::isfinite(v) && fabsf(v - target) <= tol) {
                results.push_back({r.start + i, v});
            }
        }
        if (results.size() > 20000) break; // cap
    }
    return results;
}

// Refine: keep only addresses where current value matches new_val
std::vector<ScanResult> RefineFloat(const std::vector<ScanResult>& prev, float new_val, float tol = 0.5f) {
    std::vector<ScanResult> out;
    for (auto& r : prev) {
        float cur = RMem<float>(r.addr);
        if (std::isfinite(cur) && fabsf(cur - new_val) <= tol)
            out.push_back({r.addr, cur});
    }
    return out;
}

// ─── GAME STATE — dynamically discovered addresses ────────────────────────────

struct GameAddrs {
    // discovered via scanning
    std::vector<uintptr_t> hp_addrs;      // local player HP
    std::vector<uintptr_t> pos_x_addrs;   // local player X
    std::vector<uintptr_t> pos_y_addrs;   // local player Y
    std::vector<uintptr_t> pos_z_addrs;   // local player Z
    std::vector<uintptr_t> vel_z_addrs;   // vertical velocity
    std::vector<uintptr_t> grav_addrs;    // gravity scale
    std::vector<uintptr_t> fire_addrs;    // next fire time
    std::vector<uintptr_t> dmg_addrs;     // damage multiplier
    std::vector<uintptr_t> wpn_type_addrs;// weapon type int
    bool hp_locked    = false;
    bool pos_locked   = false;
} g_addr;

// Scan state machine for HP
enum ScanState { IDLE, SCAN_HP_1, SCAN_HP_2, SCAN_POS_X1, SCAN_POS_X2,
                 SCAN_VEL, SCAN_FIRE, DONE };
static ScanState g_scan_state = IDLE;
static std::vector<ScanResult> g_scan_buf;
static float g_scan_input = 100.f;

// ─── FEATURE FLAGS ────────────────────────────────────────────────────────────

struct Feats {
    bool fist_barrett  = false;
    bool fast_shoot    = false;
    bool work_rpg      = false;
    bool fast_health   = false;
    bool lock_hp       = false;
    bool esp           = false;
    bool fly           = false;
    bool fly_up        = false;
    bool fly_down      = false;
    bool tele_save     = false;
    bool lock_enemy    = false;
    bool lock_plane    = false;
    float fly_speed    = 400.f;
    float hp_target    = 100.f;
    float dmg_multi    = 9.5f;
} g_feat;

// Saved location
float g_saved_x = 0, g_saved_y = 0, g_saved_z = 0;
bool  g_has_saved = false;

// ─── FEATURE EXECUTION ────────────────────────────────────────────────────────

void ApplyFeatures() {
    // FAST HEALTH / LOCK HP — write HP to max every frame
    if (g_feat.fast_health || g_feat.lock_hp) {
        for (auto addr : g_addr.hp_addrs)
            WMem<float>(addr, g_feat.hp_target);
    }

    // FLY — zero gravity, control vertical velocity
    if (g_feat.fly) {
        for (auto addr : g_addr.grav_addrs)
            WMem<float>(addr, 0.f);
        float vz = g_feat.fly_up ? g_feat.fly_speed :
                   g_feat.fly_down ? -g_feat.fly_speed : 0.f;
        for (auto addr : g_addr.vel_z_addrs)
            WMem<float>(addr, vz);
    }

    // FAST SHOOT — zero next fire time
    if (g_feat.fast_shoot) {
        for (auto addr : g_addr.fire_addrs)
            WMem<float>(addr, 0.f);
    }

    // FIST TO BARRETT — write damage multiplier
    if (g_feat.fist_barrett) {
        for (auto addr : g_addr.dmg_addrs)
            WMem<float>(addr, g_feat.dmg_multi);
    }

    // WORK ALL RPG — write weapon type to RPG enum
    if (g_feat.work_rpg) {
        for (auto addr : g_addr.wpn_type_addrs)
            WMem<int>(addr, 0x1F); // RPG type — adjust if needed
    }
}

// ─── SCAN WORKER (background thread) ─────────────────────────────────────────

static std::atomic<bool> g_scan_busy{false};
static std::string g_scan_status = "Ready";

void DoScanHP(float val) {
    g_scan_busy = true;
    g_scan_status = "Scanning HP...";
    auto res = ScanFloat(val, 1.0f);
    g_scan_buf = res;
    g_addr.hp_addrs.clear();
    for (auto& r : res) g_addr.hp_addrs.push_back(r.addr);
    g_scan_status = "Found " + std::to_string(res.size()) + " HP candidates";
    g_scan_busy = false;
}

void DoRefineHP(float val) {
    g_scan_busy = true;
    g_scan_status = "Refining HP...";
    g_scan_buf = RefineFloat(g_scan_buf, val, 1.0f);
    g_addr.hp_addrs.clear();
    for (auto& r : g_scan_buf) g_addr.hp_addrs.push_back(r.addr);
    g_scan_status = "Refined to " + std::to_string(g_scan_buf.size()) + " HP addresses";
    g_scan_busy = false;
}

void DoScanPosX(float val) {
    g_scan_busy = true;
    g_scan_status = "Scanning PosX...";
    auto res = ScanFloat(val, 2.0f);
    g_scan_buf = res;
    g_addr.pos_x_addrs.clear();
    for (auto& r : res) g_addr.pos_x_addrs.push_back(r.addr);
    g_scan_status = "Found " + std::to_string(res.size()) + " PosX candidates";
    g_scan_busy = false;
}

void DoRefinePosX(float val) {
    g_scan_busy = true;
    g_scan_status = "Refining PosX...";
    g_scan_buf = RefineFloat(g_scan_buf, val, 2.0f);
    g_addr.pos_x_addrs.clear();
    for (auto& r : g_scan_buf) g_addr.pos_x_addrs.push_back(r.addr);
    g_scan_status = "Refined to " + std::to_string(g_scan_buf.size()) + " PosX addresses";
    g_scan_busy = false;
}

// ─── IMGUI MENU ───────────────────────────────────────────────────────────────

static bool g_menu_open = true;
static bool g_imgui_init = false;

void DrawMenu() {
    ImGuiIO& io = ImGui::GetIO();

    // Always-visible toggle button
    ImGui::SetNextWindowPos(ImVec2(io.DisplaySize.x - 55, 5), ImGuiCond_Always);
    ImGui::SetNextWindowSize(ImVec2(50, 30), ImGuiCond_Always);
    // Fixed: removed ImGuiWindowFlags_AlwaysOnTop (not in ImGui)
    ImGui::Begin("##tog", nullptr,
        ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoBackground | ImGuiWindowFlags_NoSavedSettings);
    if (ImGui::Button("MOD")) g_menu_open = !g_menu_open;
    ImGui::End();

    if (!g_menu_open) return;

    ImGui::SetNextWindowSize(ImVec2(300, 520), ImGuiCond_Once);
    ImGui::SetNextWindowPos(ImVec2(8, 8), ImGuiCond_Once);
    ImGui::SetNextWindowBgAlpha(0.92f);

    ImGui::Begin("ROS Legacy Cheat", &g_menu_open,
        ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoSavedSettings);

    // ── COMBAT
    if (ImGui::CollapsingHeader("COMBAT", ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::Checkbox("Fist to Barrett",  &g_feat.fist_barrett);
        if (g_feat.fist_barrett)
            ImGui::SliderFloat("Dmg Multi", &g_feat.dmg_multi, 1.f, 20.f);
        ImGui::Checkbox("Fast Shoot",       &g_feat.fast_shoot);
        ImGui::Checkbox("Work All RPG",     &g_feat.work_rpg);
    }

    // ── HEALTH
    if (ImGui::CollapsingHeader("HEALTH", ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::Checkbox("Fast Health (auto-fill)", &g_feat.fast_health);
        ImGui::Checkbox("Lock HP",                 &g_feat.lock_hp);
        ImGui::SliderFloat("HP Value", &g_feat.hp_target, 1.f, 300.f);
    }

    // ── MOVEMENT
    if (ImGui::CollapsingHeader("MOVEMENT", ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::Checkbox("Fly Mode", &g_feat.fly);
        if (g_feat.fly) {
            ImGui::SliderFloat("Fly Speed", &g_feat.fly_speed, 50.f, 2000.f);
            ImGui::Text("Fly:");
            ImGui::SameLine();
            g_feat.fly_up   = ImGui::Button("  UP  ");
            ImGui::SameLine();
            g_feat.fly_down = ImGui::Button(" DOWN ");
        }
    }

    // ── TELEPORT
    if (ImGui::CollapsingHeader("TELEPORT", ImGuiTreeNodeFlags_DefaultOpen)) {
        if (ImGui::Button("Save Location", ImVec2(-1, 0))) {
            if (!g_addr.pos_x_addrs.empty() && !g_addr.pos_y_addrs.empty()) {
                g_saved_x = RMem<float>(g_addr.pos_x_addrs[0]);
                g_saved_y = RMem<float>(g_addr.pos_y_addrs[0]);
                g_saved_z = !g_addr.pos_z_addrs.empty() ?
                            RMem<float>(g_addr.pos_z_addrs[0]) : 0.f;
                g_has_saved = true;
            }
        }
        if (g_has_saved) {
            ImGui::Text("Saved: %.1f / %.1f / %.1f", g_saved_x, g_saved_y, g_saved_z);
            if (ImGui::Button("Go to Saved", ImVec2(-1, 0))) {
                for (auto a : g_addr.pos_x_addrs) WMem<float>(a, g_saved_x);
                for (auto a : g_addr.pos_y_addrs) WMem<float>(a, g_saved_y);
                for (auto a : g_addr.pos_z_addrs) WMem<float>(a, g_saved_z);
            }
        }
        ImGui::Checkbox("Lock Enemies",  &g_feat.lock_enemy);
        ImGui::Checkbox("Lock Airplane", &g_feat.lock_plane);
    }

    // ── SCANNER — teach the cheat where your HP/position is
    if (ImGui::CollapsingHeader("SCANNER (setup)", ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::TextWrapped("Use scanner to teach cheat your HP/position addresses.");
        ImGui::Text("Status: %s", g_scan_status.c_str());
        ImGui::Separator();

        // HP scanner
        ImGui::Text("HP Scanner:");
        ImGui::InputFloat("Current HP", &g_scan_input, 1.f, 10.f, "%.0f");
        bool busy = g_scan_busy.load();
        if (!busy) {
            if (ImGui::Button("1. Scan HP")) {
                std::thread([v=g_scan_input](){ DoScanHP(v); }).detach();
            }
            ImGui::SameLine();
            if (ImGui::Button("2. Refine HP")) {
                std::thread([v=g_scan_input](){ DoRefineHP(v); }).detach();
            }
        } else {
            ImGui::Text("Scanning...");
        }
        ImGui::Text("HP addresses: %zu", g_addr.hp_addrs.size());

        ImGui::Separator();
        // Position scanner
        static float pos_input = 0.f;
        ImGui::Text("Position Scanner:");
        ImGui::InputFloat("Current X pos", &pos_input, 1.f, 10.f, "%.1f");
        if (!busy) {
            if (ImGui::Button("1. Scan PosX")) {
                std::thread([v=pos_input](){ DoScanPosX(v); }).detach();
            }
            ImGui::SameLine();
            if (ImGui::Button("2. Refine PosX")) {
                std::thread([v=pos_input](){ DoRefinePosX(v); }).detach();
            }
        }
        ImGui::Text("Pos addresses: %zu", g_addr.pos_x_addrs.size());

        if (ImGui::Button("Clear All Addresses")) {
            g_addr.hp_addrs.clear();
            g_addr.pos_x_addrs.clear();
            g_addr.pos_y_addrs.clear();
            g_addr.pos_z_addrs.clear();
            g_addr.vel_z_addrs.clear();
            g_addr.grav_addrs.clear();
            g_addr.fire_addrs.clear();
            g_addr.dmg_addrs.clear();
            g_scan_buf.clear();
            g_scan_status = "Ready";
        }
    }

    ImGui::End();
}

// ─── EGL HOOK ─────────────────────────────────────────────────────────────────

typedef EGLBoolean (*PFN_eglSwap)(EGLDisplay, EGLSurface);
static PFN_eglSwap orig_eglSwap = nullptr;

EGLBoolean hook_eglSwap(EGLDisplay dpy, EGLSurface surf) {
    if (!g_imgui_init) {
        IMGUI_CHECKVERSION();
        ImGui::CreateContext();
        ImGuiIO& io = ImGui::GetIO();
        io.IniFilename = nullptr;
        ImGui::StyleColorsDark();
        auto& st = ImGui::GetStyle();
        st.WindowRounding = 7.f;
        st.FrameRounding  = 4.f;
        st.Colors[ImGuiCol_WindowBg]  = ImVec4(0.04f, 0.04f, 0.07f, 0.93f);
        st.Colors[ImGuiCol_Button]    = ImVec4(0.55f, 0.08f, 0.08f, 1.f);
        st.Colors[ImGuiCol_ButtonHovered] = ImVec4(0.75f, 0.15f, 0.15f, 1.f);
        st.Colors[ImGuiCol_Header]    = ImVec4(0.6f, 0.1f, 0.1f, 0.8f);
        ImGui_ImplAndroid_Init(nullptr);
        ImGui_ImplOpenGL3_Init("#version 300 es");
        EGLint w=0, h=0;
        eglQuerySurface(dpy, surf, EGL_WIDTH, &w);
        eglQuerySurface(dpy, surf, EGL_HEIGHT, &h);
        io.DisplaySize = ImVec2((float)w, (float)h);
        g_imgui_init = true;
        LOG("ImGui ready %dx%d", w, h);
    }

    // apply features every frame
    ApplyFeatures();

    ImGui_ImplOpenGL3_NewFrame();
    ImGui_ImplAndroid_NewFrame();
    ImGui::NewFrame();
    DrawMenu();
    ImGui::Render();
    ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

    return orig_eglSwap(dpy, surf);
}

// ─── TOUCH FORWARD ────────────────────────────────────────────────────────────

extern "C" JNIEXPORT void JNICALL
Java_com_netease_letsgo_NativeLib_onTouch(JNIEnv*, jclass,
    jint action, jfloat x, jfloat y) {
    if (!g_imgui_init) return;
    ImGuiIO& io = ImGui::GetIO();
    switch (action) {
        case 0: io.AddMouseButtonEvent(0,true);  io.AddMousePosEvent(x,y); break;
        case 1: io.AddMouseButtonEvent(0,false);                            break;
        case 2: io.AddMousePosEvent(x,y);                                   break;
    }
}

// ─── INIT ─────────────────────────────────────────────────────────────────────

void* Init(void*) {
    sleep(4);
    LOG("ROS cheat starting");

    // hook eglSwapBuffers
    void* egl = dlopen("libEGL.so", RTLD_NOW);
    if (!egl) { LOG("no libEGL"); return nullptr; }
    void* sym = dlsym(egl, "eglSwapBuffers");
    if (!sym) { LOG("no eglSwapBuffers"); return nullptr; }
    DobbyHook(sym, (void*)hook_eglSwap, (void**)&orig_eglSwap);
    LOG("eglSwapBuffers hooked");

    // initial region refresh
    RefreshRegions();
    LOG("regions loaded: %zu", g_regions.size());

    return nullptr;
}

__attribute__((constructor))
void entry() {
    pthread_t t;
    pthread_create(&t, nullptr, Init, nullptr);
    pthread_detach(t);
}
