// netcap device
// Created by liangdu on 19-12-26.
// Author liang.du@nscc-gz.cn
//  gcc cap_device.c 0o cap_device -lcap

#include<stdio.h>
#include<pcap.h>

int main(int argc,char ** argv){

    char *device;
    char error_buffer[PCAP_ERRBUF_SIZE];
    device = pcap_lookupdev(error_buffer);
    if (device == NULL){
        printf("Error finding network device:%s\n",error_buffer);
        return 1;
    }
    printf("Network Device found:%s\n",device);
    return 0;
}

