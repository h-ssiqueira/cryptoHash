package com.hss.cryptohash.util;

import java.util.Comparator;

public class ByteComparator implements Comparator<byte[]> {

    @Override
    public int compare(byte[] raw, byte[] encrypted) {
        if (encrypted.length != raw.length) {
            return 1;
        }
        var result = 0;
        for(var i = 0; encrypted.length > i; i++) {
            result |= encrypted[i] ^ raw[i];
        }
        return result;
    }
}