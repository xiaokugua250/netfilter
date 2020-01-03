.PHONY:all

TARGET_DIR = ../../bin
all: bin/cap_device_info bin/cap_device bin/cap_packet_capture bin/cap_packet_handler bin/cap_packet_type bin/cap_packet_payload
bin/cap_device:
	gcc cap_device.c -o $(TARGET_DIR)/cap_device -lpcap
bin/cap_device_info:
	gcc cap_device_info.c -o $(TARGET_DIR)/cap_device_info -lpcap
bin/cap_packet_capture:
	gcc cap_packet_capture.c -o $(TARGET_DIR)/cap_packet_capture -lpcap
bin/cap_packet_handler:
	gcc cap_packet_handler.c -o $(TARGET_DIR)/cap_packet_handler -lpcap
bin/cap_packet_type:
	gcc cap_packet_type.c -o $(TARGET_DIR)/cap_packet_type -lpcap
bin/cap_packet_payload:
	gcc cap_packet_payload.c -o $(TARGET_DIR)/cap_packet_payload -lpcap
bin/netcap:
	gcc netcap.c -o netcap -lcap
clean:
	rm -rf $(TARGET_DIR)/*