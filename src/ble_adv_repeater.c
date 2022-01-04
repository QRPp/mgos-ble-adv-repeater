#include <mgos.h>
#include <mgos_bt_gap.h>
#include <mgos_config.h>

#include <mgos-helpers/bt.h>
#include <mgos-helpers/json.h>
#include <mgos-helpers/log.h>
#include <mgos-helpers/mem.h>

QueueHandle_t advs;

struct adv_src {
  uint8_t mac[6];
  char *name;
  SLIST_ENTRY(adv_src) entry;
};
static SLIST_HEAD(, adv_src) srcs;

struct adv_src *src_find(const uint8_t mac[6]) {
  struct adv_src *s;
  SLIST_FOREACH(s, &srcs, entry) {
    if (!memcmp(s->mac, mac, sizeof(s->mac))) return s;
  }
  return NULL;
}

static bool src_parse_one(struct mg_str json) {
  struct adv_src *as = NULL;
  bool ok = false;

  void *mac = NULL;
  int macL;
  char *name = NULL;
  TRY_JSON_SCANF_OR(goto err, json.p, json.len, "{mac:%H,name:%Q}", &macL, &mac,
                    &name);
  if (!mac)
    FNERR_GT("no mac: %.*s", json.len, json.p);
  else if (macL != sizeof(as->mac))
    FNERR_GT("need %u byte %s: %.*s", sizeof(as->mac), "mac", json.len, json.p);
  else if (src_find(mac))
    FNERR_GT("duplicate: %.*s", json.len, json.p);
  as = TRY_MALLOC_OR(goto err, as);
  memcpy(as->mac, mac, sizeof(as->mac));
  as->name = name;
  SLIST_INSERT_HEAD(&srcs, as, entry);
  ok = true;

err:
  if (!ok && as) free(as);
  if (mac) free(mac);
  if (!ok && name) free(name);
  return ok;
}

static unsigned src_parse_many(struct mg_str json) {
  unsigned loaded = 0;
  void *h = NULL;
  struct json_token v;
  while ((h = json_next_elem(json.p, json.len, h, "", NULL, &v)) != NULL)
    if (src_parse_one(mg_mk_str_n(v.ptr, v.len))) loaded++;
  return loaded;
}

static void adv_queue(struct mgos_bt_gap_scan_result *r) {
  if (!uxQueueSpacesAvailable(advs)) FNERR_RET(, "queue full");

  struct mgos_bt_gap_scan_result *copy = NULL;
  copy = TRY_CALLOC_OR(goto err, copy);
  copy->adv_data = mg_strdup(r->adv_data);
  if (!copy->adv_data.p) FNERR_GT(CALL_FAILED(mg_strdup));
  if (r->scan_rsp.len) {
    copy->scan_rsp = mg_strdup(r->scan_rsp);
    if (!copy->scan_rsp.p) FNERR_GT(CALL_FAILED(mg_strdup));
  }
  copy->addr = r->addr;
  copy->rssi = r->rssi;

  if (!xQueueSendToBack(advs, &copy, 0)) FNERR_GT("queue full");
  return;

err:
  if (copy && copy->adv_data.p) free((void *) copy->adv_data.p);
  if (copy && copy->scan_rsp.p) free((void *) copy->scan_rsp.p);
  if (copy) free(copy);
}

static void adv_repeat(struct mgos_bt_gap_scan_result *r) {
  if (uxQueueMessagesWaiting(advs)) FNERR_RET(, "queue not empty");

  mgos_bt_gap_set_adv_data(r->adv_data);
  mgos_bt_gap_set_scan_rsp_data(r->scan_rsp);
  mgos_bt_gap_set_adv_enable(true);
  mgos_usleep(100 * 1000);
  mgos_bt_gap_set_adv_enable(false);
}

static void adv_handle(int ev, void *ev_data, void *userdata) {
  if (ev != MGOS_BT_GAP_EVENT_SCAN_RESULT) return;
  struct mgos_bt_gap_scan_result *r = ev_data;
  struct adv_src *as = src_find(r->addr.addr);
  if (!as) return;

  FNLOG(LL_INFO, "%s (%s) recognised (rssi %d)",
        BT_ADDR_STRA(&r->addr, MGOS_BT_ADDR_STRINGIFY_TYPE),
        as->name ?: "(null)", r->rssi);
  adv_repeat(r);
}

bool mgos_ble_adv_repeater_init() {
  SLIST_INIT(&srcs);
  advs = xQueueCreate(4, sizeof(struct mgos_bt_gap_scan_result *));
  if (!advs) FNERR_GT(CALL_FAILED(xQueueCreate));
  unsigned num = src_parse_many(mg_mk_str(mgos_sys_config_get_bt_adv_repeat()));
  FNLOG(LL_INFO, "loaded %u MAC%s", num, MUL(num));
  if (SLIST_EMPTY(&srcs)) goto err;
  mgos_event_add_group_handler(MGOS_BT_GAP_EVENT_SCAN_RESULT, adv_handle, NULL);
err:
  return true;
}
