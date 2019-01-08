chdir resources/frog
twlbannertool.exe banner.bin
copy /b srl.nds+banner.bin+tmd.bin+ctcert.bin ../frogcertXL.bin

chdir resources/dlp
twlbannertool.exe banner.bin
copy /b srl.nds+banner.bin+tmd.bin+ctcert.bin ../dlpcertXL.bin

pause