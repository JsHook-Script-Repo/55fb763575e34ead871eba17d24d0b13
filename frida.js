Java.perform(function () {
    function frida_Memory(pattern) {
        commlog.log("头部标识:" + pattern);
        //枚举内存段的属性,返回指定内存段属性地址
        var addrArray = Process.enumerateRanges("r--");
        for (var i = 0; i < addrArray.length; i++) {
            var addr = addrArray[i];
            Memory.scan(addr.base, addr.size, pattern,
                {
                    onMatch: function (address, size) {
                        commlog.log('搜索到 ' + pattern + " 地址是:" + address.toString());
                        commlog.log(hexdump(address,
                            {
                                offset: 0,
                                length: 64,
                                header: true,
                                ansi: true
                            }));
                        //0x108，0x10C如果不行，换0x100，0x104
                        var DefinitionsOffset = parseInt(address, 16) + 0x100;
                        var DefinitionsOffset_size = Memory.readInt(ptr(DefinitionsOffset));

                        var DefinitionsCount = parseInt(address, 16) + 0x104;
                        var DefinitionsCount_size = Memory.readInt(ptr(DefinitionsCount));

                        //根据两个偏移得出global-metadata大小
                        var global_metadata_size = DefinitionsOffset_size + DefinitionsCount_size
                        commlog.log("大小：", global_metadata_size);
                        if (global_metadata_size > 0) {
                            var file = new File("/storage/emulated/0/Download/global-metadata.dat", "wb");
                            file.write(Memory.readByteArray(address, global_metadata_size));
                            file.flush();
                            file.close();
                            commlog.log('导出完毕...');
                        }
                    },
                    onComplete: function () {
                        //commlog.log("搜索完毕")
                    }
                }
            );
        }
    }

    setInterval(function () {
        frida_Memory("AF 1B B1 FA 18");
    }, 5000);
});
