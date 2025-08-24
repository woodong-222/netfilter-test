#include "packet.h"

char *target_host = NULL;

int is_http_request(char *data, int len) {
    if (len < 4) return 0;
    return (strncmp(data, "GET ", 4) == 0 || 
            strncmp(data, "POST", 4) == 0 ||
            strncmp(data, "PUT ", 4) == 0 ||
            strncmp(data, "HEAD", 4) == 0);
}

char* extract_host(char *http_data, int len) {
    char *host_line = NULL;
    char *line_start = http_data;
    char *line_end = NULL;
    
    while (line_start < http_data + len) {
        line_end = strstr(line_start, "\r\n");
        if (!line_end) break;
        
        if (strncasecmp(line_start, "Host:", 5) == 0) {
            host_line = line_start + 5;
            while (*host_line == ' ') host_line++;
            
            static char host_buffer[256];
            int host_len = line_end - host_line;
            if (host_len >= 256) host_len = 255;
            strncpy(host_buffer, host_line, host_len);
            host_buffer[host_len] = '\0';
            return host_buffer;
        }
        line_start = line_end + 2;
    }
    return NULL;
}

int should_block_packet(unsigned char *data, int len) {
    if (len < sizeof(struct ip_header)) return 0;
    
    struct ip_header *ip_hdr = (struct ip_header*)data;
    if (ip_hdr->protocol != IPPROTO_TCP) return 0;
    
    int ip_header_len = (ip_hdr->version_ihl & 0x0F) * 4;
    if (len < ip_header_len + sizeof(struct tcp_header)) return 0;
    
    struct tcp_header *tcp_hdr = (struct tcp_header*)(data + ip_header_len);
    if (ntohs(tcp_hdr->dst_port) != 80) return 0;
    
    int tcp_header_len = ((tcp_hdr->data_offset_flags >> 4) & 0x0F) * 4;
    int total_header_len = ip_header_len + tcp_header_len;
    
    if (len <= total_header_len) return 0;
    
    char *http_data = (char*)(data + total_header_len);
    int http_len = len - total_header_len;
    
    if (!is_http_request(http_data, http_len)) return 0;
    
    char *host = extract_host(http_data, http_len);
    if (!host) return 0;
    
    if (strcmp(host, target_host) == 0) {
        printf("BLOCKING: %s\n", host);
        return 1;
    }
    
    return 0;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
    uint32_t id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    unsigned char *payload_data;
    int payload_len;
    
    ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) {
        id = ntohl(ph->packet_id);
    }
    
    payload_len = nfq_get_payload(nfa, &payload_data);
    
    if (payload_len >= 0 && should_block_packet(payload_data, payload_len)) {
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    }
    
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv) {
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));
    
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <host>\n", argv[0]);
        exit(1);
    }
    
    target_host = argv[1];
    printf("Blocking host: %s\n", target_host);
    
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    qh = nfq_create_queue(h, 0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }
    
    fd = nfq_fd(h);
    
    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        if (rv < 0 && errno == ENOBUFS) {
            continue;
        }
        perror("recv failed");
        break;
    }
    
    nfq_destroy_queue(qh);
    nfq_close(h);
    
    return 0;
}
