# Genbin: Binary image creation for legacy Espressif esp8266 sdk's

This tool is used to generate OTA and non OTA bin images for esp8266-nonos-sdk and old esp8266-rtos-sdk in Platformio.

It is a mix of esptool-ck and Espressif's gen_appbin.py.

It extracts the sections from an elf file and generate:
- flash.bin + irom0.text.bin or user1.bin/user2.bin
     
No intermediate file are created and no external tool are required.

Args are positionnal and similar to esptool.py.

# Examples

- To create firmware.bin and firmware.bin.irom0text.bin
	- genbin 0 dio 40m 4MB-c1 firmware.elf firmware.bin firmware.bin.irom0text.bin")
	
- To create user1.16384.new.9.bin 
	- genbin 1 dio 40m 16MB firmware.elf user1.16384.new.9.bin")
	
- To create user2.4096.new.6.bin 
	- genbin 2 dio 40m 4MB-c1 firmware.elf user2.4096.new.6.bin")
	
- To create user1.16384.new.9.bin 
	- genbin 1 dio 40m 16MB firmware.elf user1.16384.new.9.bin")
	
- To create user1.bin and user2.bin 
	- genbin 12 dio 40m 16MB firmware.elf user1.bin user2.bin")
