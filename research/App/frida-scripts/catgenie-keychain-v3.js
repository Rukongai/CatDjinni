/**
 * Hook Keychain with correct method signatures
 */

console.log('[*] Cat Genie Keychain v3 Hook');

Java.perform(function() {
    console.log('[*] Installing hooks with correct signatures...\n');

    // Hook KeychainModule.getGenericPassword with correct signature
    try {
        var KeychainModule = Java.use('com.oblador.keychain.KeychainModule');

        KeychainModule.getGenericPassword.overload(
            'java.lang.String',
            'com.facebook.react.bridge.ReadableMap',
            'com.facebook.react.bridge.Promise'
        ).implementation = function(service, options, promise) {
            console.log('\n[+] getGenericPassword called');
            console.log('    Service: ' + service);
            console.log('    Options: ' + options);

            // Wrap the promise to intercept the result
            var Promise = Java.use('com.facebook.react.bridge.Promise');
            var self = this;

            // Call original
            return this.getGenericPassword(service, options, promise);
        };
        console.log('[*] Hooked getGenericPassword');

    } catch(e) {
        console.log('[-] getGenericPassword hook failed: ' + e);
    }

    // Hook DecryptionResult constructor - this is where the secret appears
    try {
        var DecryptionResult = Java.use('com.oblador.keychain.cipherStorage.CipherStorage$DecryptionResult');

        // Try different constructor signatures
        var constructors = DecryptionResult.class.getDeclaredConstructors();
        console.log('[*] DecryptionResult constructors:');
        constructors.forEach(function(c) {
            console.log('    ' + c.toString());
        });

    } catch(e) {
        console.log('[-] DecryptionResult: ' + e);
    }

    // Hook the actual decryption at a lower level
    try {
        var CipherStorageBase = Java.use('com.oblador.keychain.cipherStorage.CipherStorageBase');

        CipherStorageBase.decrypt.implementation = function(handler, alias, key, iv, rules) {
            console.log('\n[!!!] CipherStorageBase.decrypt called');
            console.log('    Alias: ' + alias);

            var result = this.decrypt(handler, alias, key, iv, rules);

            if (result) {
                console.log('    Result class: ' + result.$className);
                // Try to get username and password fields
                try {
                    console.log('    Username: ' + result.username.value);
                    console.log('    Password: ' + result.password.value);
                    console.log('    Password length: ' + result.password.value.length);

                    if (result.password.value.length === 84) {
                        console.log('\n[!!!] FOUND 84-CHAR SECRET !!!');
                    }
                } catch(e2) {
                    console.log('    Could not read fields: ' + e2);
                }
            }

            return result;
        };
        console.log('[*] Hooked CipherStorageBase.decrypt');
    } catch(e) {
        console.log('[-] CipherStorageBase.decrypt: ' + e);
    }

    // Try hooking AES decryption directly
    try {
        var Cipher = Java.use('javax.crypto.Cipher');
        Cipher.doFinal.overload('[B').implementation = function(input) {
            var result = this.doFinal(input);

            // Check if output looks like our secret (84 bytes ASCII)
            if (result && result.length >= 80 && result.length <= 90) {
                var str = '';
                for (var i = 0; i < result.length; i++) {
                    str += String.fromCharCode(result[i] & 0xFF);
                }
                console.log('\n[!!!] Cipher.doFinal output (' + result.length + ' bytes):');
                console.log('    ' + str);

                if (result.length === 84) {
                    console.log('\n[!!!] FOUND 84-CHAR SECRET !!!');
                }
            }

            return result;
        };
        console.log('[*] Hooked Cipher.doFinal');
    } catch(e) {
        console.log('[-] Cipher.doFinal: ' + e);
    }

    console.log('\n[*] Hooks installed!\n');
});
