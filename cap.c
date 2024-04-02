#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include "radiotap/radiotap.h"
#include "radiotap/radiotap_iter.h"

#define FILTER_EXPRESSION "not ether src 54:67:51:2d:07:a9 and not ether dst 54:67:51:2d:07:a9 and (wlan[0] == 0x40) and (wlan[4:1] != 0 or wlan[5:1] != 0 or wlan[6:1] != 0 or wlan[7:1] != 0 or wlan[8:1] != 0)"

// channel map
const int wifi_channel_frequencies[] = {
    2412, 2417, 2422, 2427, 2432, 2437, 2442, 2447, 2452, 2457, 2462, 2467, 2472, 2484
};

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ieee80211_radiotap_iterator iterator;
    int hdr_len = 0;

    // Initialize the iterator with the Radiotap header
    if (ieee80211_radiotap_iterator_init(&iterator, (struct ieee80211_radiotap_header *)packet, pkthdr->len) != 0) {
        fprintf(stderr, "Error initializing Radiotap iterator\n");
        return;
    }

    int channel_index = -1; 
    int channel_freq = 0;   

    // Iterate over Radiotap header fields
    while (ieee80211_radiotap_iterator_next(&iterator) != -1) {
        // Check if this field is the channel frequency
        if (iterator.this_arg_index == IEEE80211_RADIOTAP_CHANNEL) {
            uint16_t *channel_freq_ptr = (uint16_t *)iterator.this_arg;
            int channel_number = *channel_freq_ptr;
            if (channel_number >= 1 && channel_number <= 14) {
                channel_index = channel_number - 1; // Channel numbers are 1-indexed
                channel_freq = wifi_channel_frequencies[channel_index];
                printf("Channel Frequency: %d MHz\n", channel_freq);
            }
            break; 
        }
       
        hdr_len += iterator.this_arg_size;
    }

    // Skip the Radiotap header
    packet += hdr_len;

    struct ieee80211_header {
        uint8_t frame_control[2];
        uint8_t duration[2];
        uint8_t destination_address[6];
        uint8_t source_address[6];
        uint8_t bssid[6];
        uint8_t sequence_control[2];
    };

    struct ieee80211_header *wifi_header = (struct ieee80211_header *)packet;

    uint16_t frame_control_value = (wifi_header->frame_control[1] << 8) | wifi_header->frame_control[0];
    uint8_t frame_type = (frame_control_value >> 2) & 0x03;
    uint8_t frame_subtype = (frame_control_value >> 4) & 0x0F;

    printf("IEEE 802.11 header:\n");
    printf("  Frame Control: 0x%04X\n", frame_control_value);
    printf("    Frame Type: %d\n", frame_type);
    printf("    Frame Subtype: %d\n", frame_subtype);
    printf("  Destination Address: %02X:%02X:%02X:%02X:%02X:%02X\n",
           wifi_header->destination_address[0], wifi_header->destination_address[1],
           wifi_header->destination_address[2], wifi_header->destination_address[3],
           wifi_header->destination_address[4], wifi_header->destination_address[5]);
    printf("  Source Address: %02X:%02X:%02X:%02X:%02X:%02X\n",
           wifi_header->source_address[0], wifi_header->source_address[1],
           wifi_header->source_address[2], wifi_header->source_address[3],
           wifi_header->source_address[4], wifi_header->source_address[5]);
    printf("  BSSID: %02X:%02X:%02X:%02X:%02X:%02X\n",
           wifi_header->bssid[0], wifi_header->bssid[1],
           wifi_header->bssid[2], wifi_header->bssid[3],
           wifi_header->bssid[4], wifi_header->bssid[5]);

    // Print packet contents
    printf("Packet contents:\n");
    for (int i = hdr_len; i < pkthdr->len; i++) {
        printf("%02x ", packet[i]);
        if ((i + 1) % 16 == 0)
            printf("\n");
    }
    printf("\n\n");
}

int main() {
    pcap_if_t *alldevs;
    pcap_if_t *device;
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return 1;
    }

    int count = 0;
    for (device = alldevs; device != NULL; device = device->next) {
        printf("%d. %s\n", ++count, device->name);
    }

    int choice;
    printf("Enter the number of the device you want to sniff: ");
    if (scanf("%d", &choice) != 1 || choice < 1 || choice > count) {
        fprintf(stderr, "Invalid input.\n");
        pcap_freealldevs(alldevs);
        return 1;
    }

    device = alldevs;
    for (int i = 1; i < choice; i++) {
        device = device->next;
    }

    handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device->name, errbuf);
        pcap_freealldevs(alldevs);
        return 2;
    }

    if (pcap_compile(handle, &fp, FILTER_EXPRESSION, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", FILTER_EXPRESSION, pcap_geterr(handle));
        pcap_close(handle);
        pcap_freealldevs(alldevs);
        return 2;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", FILTER_EXPRESSION, pcap_geterr(handle));
        pcap_freecode(&fp);
        pcap_close(handle);
        pcap_freealldevs(alldevs);
        return 2;
    }

    pcap_freecode(&fp);

    pcap_loop(handle, -1, packet_handler, NULL);

    pcap_close(handle);

