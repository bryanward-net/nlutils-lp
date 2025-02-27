/*
** nlscan-lp
** Built by Bryan Ward 2025
** Based on scandump by Adrian Granados.
** Copyright (c) 2023 Intuitibits LLC
** Author: Adrian Granados <adrian@intuitibits.com>
*/

#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <linux/nl80211.h>
#include <net/if.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/netlink.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define VERSION "1.2.0"

#define NL80211_GENL_FAMILY_NAME "nl80211"
#define NL80211_GENL_GROUP_NAME "scan"

#define MAX_PACKET_SIZE 2048

#ifndef min
#define min(a, b) ((a) < (b) ? (a) : (b))
#endif

char if_name[IF_NAMESIZE];

int chlookup (int f) {
  switch (f) {
    //Band 2.4
    case (2412):
      return 1;
      break;
    case (2417):
      return 2;
      break;
    case (2422):
      return 3;
      break;
    case (2427):
      return 4;
      break;
    case (2432):
      return 5;
      break;
    case (2437):
      return 6;
      break;
    case (2442):
      return 7;
      break;
    case (2447):
      return 8;
      break;
    case (2452):
      return 9;
      break;
    case (2457):
      return 10;
      break;
    case (2462):
      return 11;
      break;
    case (2467):
      return 12;
      break;
    case (2472):
      return 13;
      break;
    case (2484):
      return 14;
      break;

    //Band 5
    case (5180):
      return 36;
      break;
    case (5200):
      return 40;
      break;
    case (5220):
      return 44;
      break;
    case (5240):
      return 48;
      break;
    case (5260):
      return 52;
      break;
    case (5280):
      return 56;
      break;
    case (5300):
      return 60;
      break;
    case (5320):
      return 64;
      break;
    case (5500):
      return 100;
      break;
    case (5520):
      return 104;
      break;
    case (5540):
      return 108;
      break;
    case (5560):
      return 112;
      break;
    case (5580):
      return 116;
      break;
    case (5600):
      return 120;
      break;
    case (5620):
      return 124;
      break;
    case (5640):
      return 128;
      break;
    case (5660):
      return 132;
      break;
    case (5680):
      return 136;
      break;
    case (5700):
      return 140;
      break;
    case (5720):
      return 144;
      break;
    case (5745):
      return 149;
      break;
    case (5765):
      return 153;
      break;
    case (5785):
      return 157;
      break;
    case (5805):
      return 161;
      break;
    case (5825):
      return 165;
      break;

    //Band 6
    case (5955):
      return 1;
      break;
    case (5975):
      return 5;
      break;
    case (5995):
      return 9;
      break;
    case (6015):
      return 13;
      break;
    case (6035):
      return 17;
      break;
    case (6055):
      return 21;
      break;
    case (6075):
      return 25;
      break;
    case (6095):
      return 29;
      break;
    case (6115):
      return 33;
      break;
    case (6135):
      return 37;
      break;
    case (6155):
      return 41;
      break;
    case (6175):
      return 45;
      break;
    case (6195):
      return 49;
      break;
    case (6215):
      return 53;
      break;
    case (6235):
      return 57;
      break;
    case (6255):
      return 61;
      break;
    case (6275):
      return 65;
      break;
    case (6295):
      return 69;
      break;
    case (6315):
      return 73;
      break;
    case (6335):
      return 77;
      break;
    case (6355):
      return 81;
      break;
    case (6375):
      return 85;
      break;
    case (6395):
      return 89;
      break;
    case (6415):
      return 93;
      break;
    case (6435):
      return 97;
      break;
    case (6455):
      return 101;
      break;
    case (6475):
      return 105;
      break;
    case (6495):
      return 109;
      break;
    case (6515):
      return 113;
      break;
    case (6535):
      return 117;
      break;
    case (6555):
      return 121;
      break;
    case (6575):
      return 125;
      break;
    case (6595):
      return 129;
      break;
    case (6615):
      return 133;
      break;
    case (6635):
      return 137;
      break;
    case (6655):
      return 141;
      break;
    case (6675):
      return 145;
      break;
    case (6695):
      return 149;
      break;
    case (6715):
      return 153;
      break;
    case (6735):
      return 157;
      break;
    case (6755):
      return 161;
      break;
    case (6775):
      return 165;
      break;
    case (6795):
      return 169;
      break;
    case (6815):
      return 173;
      break;
    case (6835):
      return 177;
      break;
    case (6855):
      return 181;
      break;
    case (6875):
      return 185;
      break;
    case (6895):
      return 189;
      break;
    case (6915):
      return 193;
      break;
    case (6935):
      return 197;
      break;
    case (6955):
      return 201;
      break;
    case (6975):
      return 205;
      break;
    case (6995):
      return 209;
      break;
    case (7015):
      return 213;
      break;
    case (7035):
      return 217;
      break;
    case (7055):
      return 221;
      break;
    case (7075):
      return 225;
      break;
    case (7095):
      return 229;
      break;
    case (7115):
      return 233;
      break;

    default:
      return 0;
      break;
  }
}



struct trigger_results {
  int done;
  int aborted;
};

static const uint8_t packet_header[] = {
    // Radiotap header
    0x00, 0x00, 0x0d, 0x00, 0x28, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0xff,
    0xff,
    // 802.11 frame header
    0x80, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00,
    // 802.11 beacon header
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00};
#define PACKET_HEADER_LEN sizeof(packet_header)

static int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err,
                         void *arg) {
  int *ret = arg;
  *ret = err->error;
  return NL_STOP;
}

static int finish_handler(struct nl_msg *msg, void *arg) {
  int *ret = arg;
  *ret = 0;
  return NL_SKIP;
}

static int ack_handler(struct nl_msg *msg, void *arg) {
  int *ret = arg;
  *ret = 0;
  return NL_STOP;
}

static int no_seq_check(struct nl_msg *msg, void *arg) { return NL_OK; }

static int callback_trigger(struct nl_msg *msg, void *arg) {

  struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
  struct trigger_results *results = arg;

  if (gnlh->cmd == NL80211_CMD_SCAN_ABORTED) {
    results->done = 1;
    results->aborted = 1;
  } else if (gnlh->cmd == NL80211_CMD_NEW_SCAN_RESULTS) {
    results->done = 1;
    results->aborted = 0;
  } // else probably an uninteresting multicast message.

  return NL_SKIP;
}

static int callback_dump(struct nl_msg *msg, void *arg) {

  // Called by the kernel for each network found.
  struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
  static struct pcap_pkthdr header;
  static u_char packet[MAX_PACKET_SIZE];
  struct nlattr *tb[NL80211_ATTR_MAX + 1];
  struct nlattr *bss[NL80211_BSS_MAX + 1];
  static struct nla_policy bss_policy[NL80211_BSS_MAX + 1] = {
      [NL80211_BSS_TSF] = {.type = NLA_U64},
      [NL80211_BSS_FREQUENCY] = {.type = NLA_U32},
      [NL80211_BSS_BSSID] = {},
      [NL80211_BSS_BEACON_INTERVAL] = {.type = NLA_U16},
      [NL80211_BSS_CAPABILITY] = {.type = NLA_U16},
      [NL80211_BSS_SIGNAL_MBM] = {.type = NLA_U32},
      [NL80211_BSS_STATUS] = {.type = NLA_U32},
      [NL80211_BSS_INFORMATION_ELEMENTS] = {},
  };

  // Parse and error check.
  nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
            genlmsg_attrlen(gnlh, 0), NULL);
  if (!tb[NL80211_ATTR_BSS]) {
    return NL_SKIP;
  }

  if (nla_parse_nested(bss, NL80211_BSS_MAX, tb[NL80211_ATTR_BSS],
                       bss_policy)) {
    return NL_SKIP;
  }

  if (!bss[NL80211_BSS_BSSID])
    return NL_SKIP;
  if (!bss[NL80211_BSS_INFORMATION_ELEMENTS])
    return NL_SKIP;

  // Prepare packet with radiotap and beacon headers.
  memcpy(packet, packet_header, PACKET_HEADER_LEN);


  // Channel frequency
  uint16_t freq = nla_get_u32(bss[NL80211_BSS_FREQUENCY]);
  packet[8] = freq & 0xFF;
  packet[9] = (freq >> 8) & 0xFF;


  // Channel flags
  uint16_t channel_flags = 0x0000;
  if (freq >= 2412 && freq <= 2484) {
    channel_flags = 0x0080;
  } else if (freq >= 5150 && freq <= 5925) {
    channel_flags = 0x0100;
  }

  packet[10] = channel_flags & 0xFF;
  packet[11] = (channel_flags >> 8) & 0xFF;

  // RSSI
  int rssi = (int)nla_get_u32(bss[NL80211_BSS_SIGNAL_MBM]) / 100;
  packet[12] = rssi & 0xFF;


  // Transmitter address and BSSID
  u_char *bssid = nla_data(bss[NL80211_BSS_BSSID]);
  memcpy(&packet[23], bssid, nla_len(bss[NL80211_BSS_BSSID]));
  memcpy(&packet[29], bssid, nla_len(bss[NL80211_BSS_BSSID]));


  // Beacon TSF
  uint64_t beacon_tsf = nla_get_u64(bss[NL80211_BSS_TSF]);
  for (int i = 0; i < 8; i++) {
    packet[37 + i] = (beacon_tsf >> (i * 8)) & 0xFF;
  }

  // Beacon interval
  uint16_t beacon_int = nla_get_u16(bss[NL80211_BSS_BEACON_INTERVAL]);
  packet[45] = beacon_int & 0xFF;
  packet[46] = (beacon_int >> 8) & 0xFF;

  // Beacon capability
  uint16_t beacon_cap = nla_get_u16(bss[NL80211_BSS_CAPABILITY]);
  packet[47] = beacon_cap & 0xFF;
  packet[48] = (beacon_cap >> 8) & 0xFF;

  // IEs
  u_char *ie_data = nla_data(bss[NL80211_BSS_INFORMATION_ELEMENTS]);
  int ie_data_len = nla_len(bss[NL80211_BSS_INFORMATION_ELEMENTS]);
  int payload_len = min(ie_data_len, MAX_PACKET_SIZE - PACKET_HEADER_LEN);
  memcpy(packet + PACKET_HEADER_LEN, ie_data, payload_len);

  uint8_t ssid_len = (uint8_t)*(ie_data + 1);
  u_char ssid[ssid_len + 1];	//Length of SSID as reported plus \0
  //printf("%i\n", ssid_len);
  //printf("%c\n", *(ie_data + 2));
  memcpy(ssid, (ie_data + 2), ssid_len);
  ssid[ssid_len] = '\0';
  //printf("%s\n", ssid);

  //Escape spaces for Influx
  int j = 0;
  u_char new_ssid[2 * ssid_len + 1];
  for (int i=0; i<=ssid_len; i++) {
    if (ssid[i] == 32) {
      new_ssid[j] = '\\';
      new_ssid[j+1] = ' ';
      j+=2;
    } else {
      new_ssid[j] = ssid[i];
      j++;
    }
  }
  new_ssid[j] = '\0';
  //printf("%s\n", ssid);
  //printf("%s\n", new_ssid);



  // Update pcap header with final length values.
  header.caplen = PACKET_HEADER_LEN + payload_len;
  header.len = PACKET_HEADER_LEN + ie_data_len;
  gettimeofday(&(header.ts), NULL);

  // Write packet out.
  //pcap_dump((u_char *)dumper, &header, (u_char *)packet);

  //Line Protocol
  int chan = chlookup(freq);
  struct timeval ts;
  gettimeofday(&ts, NULL);


  char name[271];
  if (strcmp((char *)ssid,"") == 0) {
    sprintf(name, "[%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx]", *bssid, *(bssid+1), *(bssid+2), *(bssid+3), *(bssid+4), *(bssid+5));
    printf("nlscan,ifname=%s,bssid=%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx,freq=%u,channel=%u,name=%s rssi=%i %lu\n", if_name, *bssid, *(bssid+1), *(bssid+2), *(bssid+3), *(bssid+4), *(bssid+5), freq, chan, name, rssi, ts.tv_sec * 1000000000 );
  } else {
    sprintf(name, "%s\\ [%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx]", new_ssid, *bssid, *(bssid+1), *(bssid+2), *(bssid+3), *(bssid+4), *(bssid+5));
    printf("nlscan,ifname=%s,bssid=%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx,freq=%u,channel=%u,name=%s,ssid=%s rssi=%i %lu\n", if_name, *bssid, *(bssid+1), *(bssid+2), *(bssid+3), *(bssid+4), *(bssid+5), freq, chan, name, new_ssid, rssi, ts.tv_sec * 1000000000 );
  }

  return NL_SKIP;
}

int do_scan_trigger(struct nl_sock *socket, int if_index, int genl_id) {

  // Starts the scan and waits for it to finish.
  // Does not return until the scan is done or has been aborted.
  struct trigger_results results = {.done = 0, .aborted = 0};
  struct nl_msg *msg;
  struct nl_cb *cb;

  int err;
  int ret;
  int mcid = genl_ctrl_resolve_grp(socket, NL80211_GENL_FAMILY_NAME,
                                   NL80211_GENL_GROUP_NAME);
  nl_socket_add_membership(socket, mcid);

  // Allocate the message and callback handler.
  msg = nlmsg_alloc();
  if (!msg) {
    fprintf(stderr, "command failed: failed to allocate netlink message\n");
    return -ENOMEM;
  }

  cb = nl_cb_alloc(NL_CB_DEFAULT);
  if (!cb) {
    fprintf(stderr, "command failed: failed to allocate netlink callback\n");
    nlmsg_free(msg);
    return -ENOMEM;
  }

  // Setup the message and callback handlers.
  genlmsg_put(msg, 0, 0, genl_id, 0, 0, NL80211_CMD_TRIGGER_SCAN, 0);
  nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_index);
  nla_put(msg, NL80211_ATTR_SCAN_SSIDS, 0, NULL);
  nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, callback_trigger, &results);
  nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &err);
  nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);
  nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err);
  nl_cb_set(cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, no_seq_check, NULL);

  // Send NL80211_CMD_TRIGGER_SCAN to start the scan.
  // The kernel may reply with NL80211_CMD_NEW_SCAN_RESULTS on success or
  // NL80211_CMD_SCAN_ABORTED if another scan was started by another process.
  err = 1;
  ret = nl_send_auto(socket, msg); // Send the message.

  while (err > 0)
    ret = nl_recvmsgs(
        socket,
        cb); // First wait for ack_handler(). This helps with basic errors.
  if (ret < 0) {
    fprintf(stderr, "command failed: %s (%d)\n", nl_geterror(-ret), err);
    return err;
  }

  while (!results.done)
    nl_recvmsgs(socket, cb);
  if (results.aborted) {
    fprintf(stderr, "command failed: scan aborted\n");
    return 1;
  }

  // Cleanup
  nlmsg_free(msg);
  nl_cb_put(cb);
  nl_socket_drop_membership(socket, mcid);
  return 0;
}

int main(int argc, char *argv[]) {

  struct nl_sock *socket;
  int err;
  pcap_t *handle;
  int linktype = DLT_IEEE802_11_RADIO;
  int snaplen = 65535;

  if (argc == 2) {
    if (strcmp(argv[1], "-v") == 0) {
      printf("%s version %s\nBuilt by Bryan Ward, based on scandump by Adrian Granados\n", basename(argv[0]), VERSION);
      return EXIT_SUCCESS;
    }
  }

  if (argc != 2 || strcmp(argv[1], "-h") == 0) {
    printf("Usage: %s <interface>\n", basename(argv[0]));
    printf("       %s -v\n", basename(argv[0]));
    printf("%s version %s\nBuilt by Bryan Ward, based on scandump by Adrian Granados\n", basename(argv[0]), VERSION);	
    return EXIT_FAILURE;
  }

  int if_index = if_nametoindex(argv[1]);
  //Convert if_index to the proper ifname the system uses
  if_indextoname(if_index, if_name);
  //fprintf(stderr, "IF_NAME: %s", if_name);

  socket = nl_socket_alloc();
  if (!socket) {
    fprintf(stderr, "command failed: %s (%d)\n", strerror(errno), errno);
    return -1;
  }

  err = genl_connect(socket);
  if (err < 0) {
    fprintf(stderr, "command failed: %s (%d)\n", nl_geterror(err), err);
    nl_socket_free(socket);
    return -1;
  }

  int genl_id = genl_ctrl_resolve(socket, NL80211_GENL_FAMILY_NAME);
  if (genl_id < 0) {
    fprintf(stderr, "command failed: %s (%d)\n", nl_geterror(genl_id), genl_id);
    nl_socket_free(socket);
    return -1;
  }

  // Create pcap handle
  handle = pcap_open_dead(linktype, snaplen);
  if (!handle) {
    fprintf(stderr, "command failed: error creating pcap handle\n");
    nl_socket_free(socket);
    return -1;
  }

  while (1) {

    // Trigger scan and wait for it to finish
    int err = do_scan_trigger(socket, if_index, genl_id);
    if (err != 0) {
      // Errors -16 (-EBUSY), -25 (-ENOTTY), or -33 (-EDOM)
      // can happen for various reasons when doing a scan
      // but we can simply retry.
      if (err == -EBUSY || err == -ENOTTY || err == -EDOM) {
        sleep(2);
        continue;
      }

      // Other errors are not expected, so we quit.
      return err;
    }

    // Dump networks found into file.
    struct nl_msg *msg = nlmsg_alloc();
    genlmsg_put(msg, 0, 0, genl_id, 0, NLM_F_DUMP, NL80211_CMD_GET_SCAN, 0);
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_index);
    nl_socket_modify_cb(socket, NL_CB_VALID, NL_CB_CUSTOM, callback_dump, 0);
    int ret = nl_send_auto(socket, msg);
    ret = nl_recvmsgs_default(socket);
    nlmsg_free(msg);

    if (ret < 0) {
      fprintf(stderr, "warning: %s (%d)\n", nl_geterror(-ret), ret);
    }

  }

  return 0;
}
