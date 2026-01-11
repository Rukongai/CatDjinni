/**
 * Capture JWT tokens and signature components for verification
 */

console.log('[*] Auth Capture Hook v2');

Java.perform(function() {
    console.log('[*] Installing auth hooks...\n');

    // Hook the React Native networking module with correct signature (double instead of int)
    try {
        var NetworkingModule = Java.use('com.facebook.react.modules.network.NetworkingModule');

        NetworkingModule.sendRequest.overload(
            'java.lang.String',
            'java.lang.String',
            'double',
            'com.facebook.react.bridge.ReadableArray',
            'com.facebook.react.bridge.ReadableMap',
            'java.lang.String',
            'boolean',
            'double',
            'boolean'
        ).implementation = function(method, url, requestId, headers, data, responseType, incrementalUpdates, timeout, withCredentials) {
            console.log('\n[+] HTTP Request:');
            console.log('    Method: ' + method);
            console.log('    URL: ' + url);

            if (headers !== null) {
                var size = headers.size();
                for (var i = 0; i < size; i++) {
                    var headerPair = headers.getArray(i);
                    if (headerPair !== null && headerPair.size() >= 2) {
                        var name = headerPair.getString(0);
                        var value = headerPair.getString(1);

                        // Print all signature and auth headers
                        var nameLower = name.toLowerCase();
                        if (nameLower === 'authorization' ||
                            nameLower.indexOf('y-pm-sg') !== -1 ||
                            nameLower.indexOf('x-pm-en') !== -1 ||
                            nameLower.indexOf('x-render') !== -1) {
                            console.log('    ' + name + ': ' + value);
                        }
                    }
                }
            }

            if (data !== null) {
                try {
                    console.log('    Body: ' + JSON.stringify(data.toHashMap()));
                } catch(e) {}
            }

            return this.sendRequest(method, url, requestId, headers, data, responseType, incrementalUpdates, timeout, withCredentials);
        };
        console.log('[*] Hooked NetworkingModule.sendRequest');
    } catch(e) {
        console.log('[-] NetworkingModule: ' + e);
    }

    // Hook AsyncStorage with correct signature
    try {
        var AsyncStorageModule = Java.use('com.reactnativecommunity.asyncstorage.AsyncStorageModule');

        AsyncStorageModule.multiGet.overload(
            'com.facebook.react.bridge.ReadableArray',
            'com.facebook.react.bridge.Callback'
        ).implementation = function(keys, callback) {
            console.log('\n[+] AsyncStorage.multiGet:');
            if (keys !== null) {
                var size = keys.size();
                for (var i = 0; i < size; i++) {
                    var key = keys.getString(i);
                    if (key.indexOf('token') !== -1 ||
                        key.indexOf('Token') !== -1 ||
                        key.indexOf('userData') !== -1 ||
                        key.indexOf('user') !== -1) {
                        console.log('    Key: ' + key);
                    }
                }
            }
            return this.multiGet(keys, callback);
        };
        console.log('[*] Hooked AsyncStorageModule.multiGet');
    } catch(e) {
        console.log('[-] AsyncStorage: ' + e);
    }

    // Hook SQLite to capture stored data
    try {
        var SQLiteDatabase = Java.use('android.database.sqlite.SQLiteDatabase');
        SQLiteDatabase.rawQuery.overload('java.lang.String', '[Ljava.lang.String;').implementation = function(sql, args) {
            var result = this.rawQuery(sql, args);

            // Log queries for token-related data
            if (sql.indexOf('catalystLocalStorage') !== -1 ||
                sql.indexOf('token') !== -1 ||
                sql.indexOf('userData') !== -1) {
                console.log('\n[+] SQLite query: ' + sql);
                if (args) {
                    for (var i = 0; i < args.length; i++) {
                        console.log('    Arg ' + i + ': ' + args[i]);
                    }
                }
            }

            return result;
        };
        console.log('[*] Hooked SQLiteDatabase.rawQuery');
    } catch(e) {
        console.log('[-] SQLite: ' + e);
    }

    console.log('\n[*] Auth hooks installed - interact with the app!\n');
});
