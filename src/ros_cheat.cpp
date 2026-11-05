// ROS Legacy — Runtime Memory Scanner Cheat
// Android ARM64, NDK C++17
// No Dobby — uses direct PLT/GOT hook via dlopen+dlsym

#include <jni.h>
#include <android/log.h>
#include <EGL/egl.h>
#include <GLES3/gl3.h>
#include <dlfcn.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/mman.h>
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

#define TAG "ROS_CHEAT"
#define LOG(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)

// ─── INLINE HOOK (no Dobby needed) ───────────────────────────────────────────
// ARM64: overwrite first 16 bytes with LDR X17, #8 / BR X17 / <abs64 addr>

static bool WriteHook(void* target, void* replacement, void** original) {
    // Save original bytes for trampoline
    static uint8_t tramp[32];
    memcpy(tramp, target, 16);
    // Add branch back after the 16 stolen bytes
    uintptr_t ret_addr = (uintptr_t)target + 16;
    uint32_t ldr  = 0x58000051; // LDR X17, #8
    uint32_t br   = 0xD61F0220; // BR X17
    memcpy(tramp + 16, &ldr, 4);
    memcpy(tramp + 20, &br,  4);
    memcpy(tramp + 24, &ret_addr, 8);

    // Make trampoline executable
    uintptr_t tp = (uintptr_t)tramp;
    mprotect((void*)(tp & ~0xFFF), 0x2000, PROT_READ|PROT_WRITE|PROT_EXEC);
    __builtin___clear_cache(tramp, tramp + 32);
    *original = tramp;

    // Write hook into target
    uintptr_t tgt = (uintptr_t)target;
    mprotect((void*)(tgt & ~0xFFF), 0x2000, PROT_READ|PROT_WRITE|PROT_EXEC);
    uint32_t patch[4];
    patch[0] = 0x58000051; // LDR X17, #8
    patch[1] = 0xD61F0220; // BR X17
    uintptr_t rep = (uintptr_t)replacement;
    memcpy(&patch[2], &rep, 8);
    memcpy(target, patch, 16);
    __builtin___clear_cache(target, (uint8_t*)target + 16);
    return true;
}

// ─── MEMORY ──────────────────────────────────────────────────────────────────

struct MemRegion { uintptr_t start, end; };
static std::vector<MemRegion> g_regions;
static std::mutex g_region_mutex;
static int g_mem_fd = -1;

void RefreshRegions() {
    std::lock_guard<std::mutex> lk(g_region_mutex);
    g_regions.clear();
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        uintptr_t s, e; char perms[8];
        if (sscanf(line, "%lx-%lx %4s", &s, &e, perms) != 3) continue;
        if (perms[0] != 'r') continue;
        if ((e - s) < 4 || (e - s) > 64*1024*1024) continue;
        if (strstr(line, "[vdso]") || strstr(line, "[stack]")) continue;
        g_regions.push_back({s, e});
    }
    fclose(f);
}

bool SafeRead(uintptr_t addr, void* out, size_t sz) {
    if (g_mem_fd < 0) g_mem_fd = open("/proc/self/mem", O_RDONLY);
    if (g_mem_fd < 0) return false;
    return pread64(g_mem_fd, out, sz, (off64_t)addr) == (ssize_t)sz;
}

void SafeWrite(uintptr_t addr, const void* in, size_t sz) {
    memcpy((void*)addr, in, sz);
}

template<typename T> T    RMem(uintptr_t a) { T v{}; SafeRead(a,&v,sizeof(T)); return v; }
template<typename T> void WMem(uintptr_t a, T v) { SafeWrite(a,&v,sizeof(T)); }

// ─── SCANNER ─────────────────────────────────────────────────────────────────

struct ScanResult { uintptr_t addr; float val; };
static std::vector<ScanResult> g_scan_buf;
static std::atomic<bool> g_scan_busy{false};
static std::string g_scan_status = "Ready";

std::vector<ScanResult> ScanFloat(float target, float tol) {
    std::vector<ScanResult> results;
    RefreshRegions();
    std::lock_guard<std::mutex> lk(g_region_mutex);
    for (auto& r : g_regions) {
        size_t sz = r.end - r.start;
        std::vector<uint8_t> buf(sz);
        if (!SafeRead(r.start, buf.data(), sz)) continue;
        for (size_t i = 0; i+4 <= sz; i += 4) {
            float v; memcpy(&v, buf.data()+i, 4);
            if (std::isfinite(v) && fabsf(v-target) <= tol)
                results.push_back({r.start+i, v});
        }
        if (results.size() > 20000) break;
    }
    return results;
}

std::vector<ScanResult> RefineFloat(const std::vector<ScanResult>& prev, float nv, float tol) {
    std::vector<ScanResult> out;
    for (auto& r : prev) {
        float cur = RMem<float>(r.addr);
        if (std::isfinite(cur) && fabsf(cur-nv) <= tol)
            out.push_back({r.addr, cur});
    }
    return out;
}

// ─── GAME ADDRESSES ──────────────────────────────────────────────────────────

struct GameAddrs {
    std::vector<uintptr_t> hp, pos_x, pos_y, pos_z, vel_z, grav, fire, dmg;
} g_addr;

// ─── FEATURES ────────────────────────────────────────────────────────────────

struct Feats {
    bool fist_barrett=false, fast_shoot=false, work_rpg=false;
    bool fast_health=false,  lock_hp=false,    fly=false;
    bool fly_up=false,       fly_down=false;
    bool lock_enemy=false,   lock_plane=false;
    float fly_speed=400.f, hp_target=100.f, dmg_multi=9.5f;
} g_feat;

float g_saved_x=0, g_saved_y=0, g_saved_z=0;
bool  g_has_saved=false;

void ApplyFeatures() {
    if (g_feat.fast_health || g_feat.lock_hp)
        for (auto a : g_addr.hp) WMem<float>(a, g_feat.hp_target);
    if (g_feat.fly) {
        for (auto a : g_addr.grav) WMem<float>(a, 0.f);
        float vz = g_feat.fly_up ? g_feat.fly_speed : g_feat.fly_down ? -g_feat.fly_speed : 0.f;
        for (auto a : g_addr.vel_z) WMem<float>(a, vz);
    }
    if (g_feat.fast_shoot)   for (auto a : g_addr.fire) WMem<float>(a, 0.f);
    if (g_feat.fist_barrett) for (auto a : g_addr.dmg)  WMem<float>(a, g_feat.dmg_multi);
    if (g_feat.work_rpg)     for (auto a : g_addr.dmg)  WMem<int>(a, 0x1F);
}

// ─── SCAN WORKERS ────────────────────────────────────────────────────────────

void DoScan(float v, bool refine, std::vector<uintptr_t>& out, const char* lbl, float tol=1.f) {
    g_scan_busy=true;
    g_scan_status = std::string(refine?"Refining ":"Scanning ") + lbl + "...";
    if (!refine) g_scan_buf = ScanFloat(v, tol);
    else         g_scan_buf = RefineFloat(g_scan_buf, v, tol);
    out.clear();
    for (auto& r : g_scan_buf) out.push_back(r.addr);
    g_scan_status = std::string(lbl) + ": " + std::to_string(out.size()) + " addrs";
    g_scan_busy=false;
}

// ─── MENU ─────────────────────────────────────────────────────────────────────

static bool g_menu_open=true, g_imgui_init=false;
static float g_hp_input=100.f, g_pos_input=0.f;

void DrawMenu() {
    ImGuiIO& io = ImGui::GetIO();

    // Toggle button
    ImGui::SetNextWindowPos(ImVec2(io.DisplaySize.x-55,5), ImGuiCond_Always);
    ImGui::SetNextWindowSize(ImVec2(50,30), ImGuiCond_Always);
    ImGui::Begin("##tog", nullptr,
        ImGuiWindowFlags_NoDecoration|ImGuiWindowFlags_NoMove|
        ImGuiWindowFlags_NoBackground|ImGuiWindowFlags_NoSavedSettings);
    if (ImGui::Button("MOD")) g_menu_open=!g_menu_open;
    ImGui::End();

    if (!g_menu_open) return;

    ImGui::SetNextWindowSize(ImVec2(300,540), ImGuiCond_Once);
    ImGui::SetNextWindowPos(ImVec2(8,8), ImGuiCond_Once);
    ImGui::SetNextWindowBgAlpha(0.93f);
    ImGui::Begin("ROS Legacy Cheat", &g_menu_open,
        ImGuiWindowFlags_NoCollapse|ImGuiWindowFlags_NoResize|ImGuiWindowFlags_NoSavedSettings);

    if (ImGui::CollapsingHeader("COMBAT", ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::Checkbox("Fist to Barrett", &g_feat.fist_barrett);
        if (g_feat.fist_barrett) ImGui::SliderFloat("Dmg Multi",&g_feat.dmg_multi,1.f,20.f);
        ImGui::Checkbox("Fast Shoot",   &g_feat.fast_shoot);
        ImGui::Checkbox("Work All RPG", &g_feat.work_rpg);
    }
    if (ImGui::CollapsingHeader("HEALTH", ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::Checkbox("Fast Health", &g_feat.fast_health);
        ImGui::Checkbox("Lock HP",     &g_feat.lock_hp);
        ImGui::SliderFloat("HP Value", &g_feat.hp_target, 1.f, 300.f);
    }
    if (ImGui::CollapsingHeader("MOVEMENT", ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::Checkbox("Fly Mode", &g_feat.fly);
        if (g_feat.fly) {
            ImGui::SliderFloat("Speed",&g_feat.fly_speed,50.f,2000.f);
            ImGui::Text("Fly:"); ImGui::SameLine();
            g_feat.fly_up   = ImGui::Button("  UP  "); ImGui::SameLine();
            g_feat.fly_down = ImGui::Button(" DOWN ");
        }
    }
    if (ImGui::CollapsingHeader("TELEPORT", ImGuiTreeNodeFlags_DefaultOpen)) {
        if (ImGui::Button("Save Location", ImVec2(-1,0)) && !g_addr.pos_x.empty()) {
            g_saved_x = RMem<float>(g_addr.pos_x[0]);
            g_saved_y = !g_addr.pos_y.empty() ? RMem<float>(g_addr.pos_y[0]) : 0.f;
            g_saved_z = !g_addr.pos_z.empty() ? RMem<float>(g_addr.pos_z[0]) : 0.f;
            g_has_saved=true;
        }
        if (g_has_saved) {
            ImGui::Text("Saved: %.1f/%.1f/%.1f", g_saved_x,g_saved_y,g_saved_z);
            if (ImGui::Button("Go to Saved", ImVec2(-1,0))) {
                for (auto a:g_addr.pos_x) WMem<float>(a,g_saved_x);
                for (auto a:g_addr.pos_y) WMem<float>(a,g_saved_y);
                for (auto a:g_addr.pos_z) WMem<float>(a,g_saved_z);
            }
        }
        ImGui::Checkbox("Lock Enemies",  &g_feat.lock_enemy);
        ImGui::Checkbox("Lock Airplane", &g_feat.lock_plane);
    }
    if (ImGui::CollapsingHeader("SCANNER", ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::Text("%s", g_scan_status.c_str());
        bool busy=g_scan_busy.load();
        ImGui::InputFloat("HP value",&g_hp_input,1.f,10.f,"%.0f");
        if (!busy) {
            if (ImGui::Button("Scan HP"))
                std::thread([v=g_hp_input]{ DoScan(v,false,g_addr.hp,"HP"); }).detach();
            ImGui::SameLine();
            if (ImGui::Button("Refine HP"))
                std::thread([v=g_hp_input]{ DoScan(v,true,g_addr.hp,"HP"); }).detach();
        }
        ImGui::InputFloat("X pos",&g_pos_input,1.f,10.f,"%.1f");
        if (!busy) {
            if (ImGui::Button("Scan PosX"))
                std::thread([v=g_pos_input]{ DoScan(v,false,g_addr.pos_x,"PosX",2.f); }).detach();
            ImGui::SameLine();
            if (ImGui::Button("Refine PosX"))
                std::thread([v=g_pos_input]{ DoScan(v,true,g_addr.pos_x,"PosX",2.f); }).detach();
        }
        if (ImGui::Button("Clear All")) {
            g_addr.hp.clear(); g_addr.pos_x.clear(); g_addr.pos_y.clear();
            g_addr.pos_z.clear(); g_addr.vel_z.clear(); g_addr.grav.clear();
            g_addr.fire.clear(); g_addr.dmg.clear();
            g_scan_buf.clear(); g_scan_status="Ready";
        }
    }
    ImGui::End();
}

// ─── EGL HOOK ────────────────────────────────────────────────────────────────

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
        st.WindowRounding=7.f; st.FrameRounding=4.f;
        st.Colors[ImGuiCol_WindowBg]      = ImVec4(0.04f,0.04f,0.07f,0.93f);
        st.Colors[ImGuiCol_Button]        = ImVec4(0.55f,0.08f,0.08f,1.f);
        st.Colors[ImGuiCol_ButtonHovered] = ImVec4(0.75f,0.15f,0.15f,1.f);
        st.Colors[ImGuiCol_Header]        = ImVec4(0.6f,0.1f,0.1f,0.8f);
        ImGui_ImplAndroid_Init(nullptr);
        ImGui_ImplOpenGL3_Init("#version 300 es");
        EGLint w=0,h=0;
        eglQuerySurface(dpy,surf,EGL_WIDTH,&w);
        eglQuerySurface(dpy,surf,EGL_HEIGHT,&h);
        io.DisplaySize=ImVec2((float)w,(float)h);
        g_imgui_init=true;
        LOG("ImGui ready %dx%d",w,h);
    }
    ApplyFeatures();
    ImGui_ImplOpenGL3_NewFrame();
    ImGui_ImplAndroid_NewFrame();
    ImGui::NewFrame();
    DrawMenu();
    ImGui::Render();
    ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
    return orig_eglSwap(dpy,surf);
}

// ─── TOUCH ───────────────────────────────────────────────────────────────────

extern "C" JNIEXPORT void JNICALL
Java_com_netease_letsgo_NativeLib_onTouch(JNIEnv*,jclass,jint action,jfloat x,jfloat y) {
    if (!g_imgui_init) return;
    ImGuiIO& io=ImGui::GetIO();
    switch(action){
        case 0: io.AddMouseButtonEvent(0,true); io.AddMousePosEvent(x,y); break;
        case 1: io.AddMouseButtonEvent(0,false); break;
        case 2: io.AddMousePosEvent(x,y); break;
    }
}

// ─── INIT ────────────────────────────────────────────────────────────────────

void* Init(void*) {
    sleep(4);
    LOG("ROS cheat starting");
    void* egl = dlopen("libEGL.so", RTLD_NOW);
    if (!egl) { LOG("no libEGL"); return nullptr; }
    void* sym = dlsym(egl, "eglSwapBuffers");
    if (!sym) { LOG("no eglSwapBuffers"); return nullptr; }
    WriteHook(sym, (void*)hook_eglSwap, (void**)&orig_eglSwap);
    LOG("eglSwapBuffers hooked");
    RefreshRegions();
    return nullptr;
}

__attribute__((constructor))
void entry() {
    pthread_t t;
    pthread_create(&t,nullptr,Init,nullptr);
    pthread_detach(t);
}
