#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define TUN_DEVICE "tun0"
#define BUF_SIZE 2048

int tun_alloc(char *dev) {
  int fd = open("/dev/net/tun", O_RDWR);
  if (fd < 0) {
    perror("Opening /dev/net/tun");
    return -1;
  }

  struct ifreq ifr = {
    .ifr_flags = IFF_TUN | IFF_NO_PI,
  };
  if (*dev)
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);

  int err = ioctl(fd, TUNSETIFF, (void *)&ifr);
  if (err < 0) {
    perror("ioctl(TUNSETIFF)");
    close(fd);
    return err;
  }

  strcpy(dev, ifr.ifr_name);

  return fd;
}

uint16_t cksum(uint16_t *ptr, int nbytes) {
  int8_t sum = 0;
  while (nbytes > 1) {
    sum += *ptr++;
    nbytes -= 2;
  }

  if (nbytes == 1)
    sum += *(uint8_t *)ptr & 0xff;

  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);

  return (uint16_t)~sum;
}

int main() {
  char tun_name[IFNAMSIZ];
  strcpy(tun_name, TUN_DEVICE);

  int tun_fd = tun_alloc(tun_name);
  if (tun_fd < 0) {
    fprintf(stderr, "Error allocating interface\n");
    exit(1);
  }

  printf("TUN device %s allocated. Waiting for packets...\n", tun_name);

  uint8_t buf[BUF_SIZE];

  while (1) {
    int nread = read(tun_fd, buf, sizeof(buf));
    if (nread < 0) {
      perror("Reading from interface");
      close(tun_fd);
      exit(1);
    }

    struct iphdr *iph = (struct iphdr *)buf;
    if (iph->version != 4 || iph->protocol != IPPROTO_UDP) {
      // fprintf(stderr, "Unsupported packet\n");
      continue;
    }

    struct udphdr *udph = (struct udphdr *)(buf + (iph->ihl * 4));
    uint8_t *udp_data = buf + (iph->ihl * 4) + sizeof(struct udphdr);
    int32_t udp_data_len = nread - (iph->ihl * 4) - sizeof(struct udphdr);

    char ip_src[INET_ADDRSTRLEN];
    char ip_dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &iph->saddr, ip_src, sizeof(ip_src));
    inet_ntop(AF_INET, &iph->daddr, ip_dst, sizeof(ip_dst));

    printf("[Received UDP] Src: %s:%d -> Dst: %s:%d | Len: %d\n",
            ip_src, ntohs(udph->source),
            ip_dst, ntohs(udph->dest),
            udp_data_len);

    if (udp_data_len > 0) {
      char print_buf[BUF_SIZE];
      int safe_len = (udp_data_len < sizeof(print_buf) - 1) ? udp_data_len : sizeof(print_buf) - 1;
      memcpy(print_buf, udp_data, safe_len);
      print_buf[safe_len] = '\0';
      printf("  Payload: %s", print_buf);
    }

    // -- Echo Reply の作成 --
    // 2. IP アドレスの入れ替え
    uint32_t tmp_ip = iph->saddr;
    iph->saddr = iph->daddr;
    iph->daddr = tmp_ip;

    // 3. UDPポートの入れ替え
    uint16_t tmp_port = udph->source;
    udph->source = udph->dest;
    udph->dest = tmp_port;

    // 4. UDPチェックサムの無効化 (IPv4では 0 が許可されている)
    udph->check = 0;

    // 5. IP チェックサムの再計算
    iph->check = 0;
    iph->check = cksum((uint16_t *)buf, iph->ihl * 4);

    printf("  [Action] Swapped src/dst and sending back...\n");

    write(tun_fd, buf, nread);
  }

  return 0;
}