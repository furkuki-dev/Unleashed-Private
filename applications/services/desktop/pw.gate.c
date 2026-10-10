#include "pw_gate.h"
#include <furi.h>
#include <gui/gui.h>
#include <gui/view_dispatcher.h>
#include <gui/modules/text_input.h>
#include <storage/storage.h>
#include <toolbox/version.h>

#define PW_SALT "UPR1v"
#define PW_HASH 0xfdbfcd2bf2a80951ULL // salted FNV-1a от "Tester1"
#define PW_MARK "/int/.pwok"
#define PW_MAX  24

typedef struct {
    ViewDispatcher* vd;
    TextInput* ti;
    char buf[PW_MAX + 1];
} PwCtx;

static uint64_t pw_hash(const char* s) {
    uint64_t h = 0xcbf29ce484222325ULL;
    for(const char* p = PW_SALT; *p; p++) {
        h ^= (uint8_t)*p;
        h *= 0x100000001b3ULL;
    }
    for(; *s; s++) {
        h ^= (uint8_t)*s;
        h *= 0x100000001b3ULL;
    }
    return h;
}

static bool pw_marked(void) {
    bool ok = false;
    Storage* st = furi_record_open(RECORD_STORAGE);
    File* f = storage_file_alloc(st);
    if(storage_file_open(f, PW_MARK, FSAM_READ, FSOM_OPEN_EXISTING)) {
        char buf[32] = {0};
        storage_file_read(f, buf, sizeof(buf) - 1);
        ok = (strcmp(buf, version_get_githash(NULL)) == 0);
        storage_file_close(f);
    }
    storage_file_free(f);
    furi_record_close(RECORD_STORAGE);
    return ok;
}

static void pw_mark(void) {
    Storage* st = furi_record_open(RECORD_STORAGE);
    File* f = storage_file_alloc(st);
    if(storage_file_open(f, PW_MARK, FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        const char* h = version_get_githash(NULL);
        storage_file_write(f, h, strlen(h));
        storage_file_close(f);
    }
    storage_file_free(f);
    furi_record_close(RECORD_STORAGE);
}

static bool pw_nav(void* ctx) {
    UNUSED(ctx);
    return true; // кнопка Back не выходит из ввода
}

static void pw_done(void* ctx) {
    PwCtx* c = ctx;
    if(pw_hash(c->buf) == PW_HASH) {
        view_dispatcher_stop(c->vd);
    } else {
        memset(c->buf, 0, sizeof(c->buf));
        text_input_set_header_text(c->ti, "Wrong password");
        text_input_set_result_callback(c->ti, pw_done, c, c->buf, sizeof(c->buf), true);
    }
}

void pw_gate_run(void) {
    if(pw_marked()) return;

    PwCtx c = {0};
    Gui* gui = furi_record_open(RECORD_GUI);
    c.vd = view_dispatcher_alloc();
    c.ti = text_input_alloc();

    view_dispatcher_set_event_callback_context(c.vd, &c);
    view_dispatcher_set_navigation_event_callback(c.vd, pw_nav);
    view_dispatcher_add_view(c.vd, 0, text_input_get_view(c.ti));
    view_dispatcher_attach_to_gui(c.vd, gui, ViewDispatcherTypeFullscreen);

    text_input_set_header_text(c.ti, "Password");
    text_input_set_result_callback(c.ti, pw_done, &c, c.buf, sizeof(c.buf), true);

    view_dispatcher_switch_to_view(c.vd, 0);
    view_dispatcher_run(c.vd);

    view_dispatcher_remove_view(c.vd, 0);
    text_input_free(c.ti);
    view_dispatcher_free(c.vd);
    furi_record_close(RECORD_GUI);

    pw_mark();
}
