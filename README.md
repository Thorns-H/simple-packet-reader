# 🌐 Simple Ethernet Packet Reader

This program can ready binary files (packages) and reformat every single byte on them, following the logic from the ethernet frame,
we can check how many bytes are from ethernet data, the ethertype, the destination and source mac addreses.

You may need some prerequisites to run this program :
```
sudo apt-get install libpcap-dev
pip3 install Cython
pip3 install python-libpcap
```

To check this out, just run the main file :
```
sudo -E python3 run.py
```

**ⓘ Important:** <br />
* If you want to test it out with any packages you have, just add them to `test_files/your_file.bin`, the script will read them.
* I'm planning on making this bigger, for now it just can read ethernet packages, take this on count.
* Use `pcap` on the terminal input to change to live packet capture.
* You can install [Hex Editor](https://marketplace.visualstudio.com/items?itemName=ms-vscode.hexeditor) and try using it with 
VS Code so you can check if the outputs are correct.

## Ethernet Frame
<p align="center">
  <img src="https://www.ionos.es/digitalguide/fileadmin/DigitalGuide/Screenshots_2018/EN-ethernet-frame-structure.jpg"/>
</p>
