/*
 * Copyright (c) 2022 CriticalBlue Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
 * documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
 * WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

package dev.koller.certificate_pinning_httpclient;

import android.util.Log;

import androidx.annotation.NonNull;

import java.net.URL;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import io.flutter.embedding.engine.plugins.FlutterPlugin;
import io.flutter.plugin.common.BinaryMessenger;
import io.flutter.plugin.common.MethodCall;
import io.flutter.plugin.common.MethodChannel;
import io.flutter.plugin.common.MethodChannel.MethodCallHandler;
import io.flutter.plugin.common.MethodChannel.Result;
import io.flutter.plugin.common.StandardMethodCodec;

// CertificatePinningHttpClientPlugin provides the bridge to the Approov SDK itself. Methods are initiated using the
// MethodChannel to call various methods within the SDK. A facility is also provided to probe the certificates
// presented on any particular URL to implement the pinning. Note that the MethodChannel must run on a background
// thread since it makes blocking calls.
public class CertificatePinningHttpClientPlugin implements FlutterPlugin, MethodCallHandler {

    // The MethodChannel for the communication between Flutter and native Android
    //
    // This local reference serves to register the plugin with the Flutter Engine and unregister it
    // when the Flutter Engine is detached from the Activity
    private MethodChannel channel;

    // Connect timeout (in ms) for host certificate fetch
    private static final int FETCH_CERTIFICATES_TIMEOUT_MS = 3000;

    // Application context passed to Approov initialization

    // Provides any prior initial configuration supplied, to allow a reinitialization caused by
    // a hot restart if the configuration is the same
    private static String initializedConfig;

    @Override
    public void onAttachedToEngine(@NonNull FlutterPluginBinding flutterPluginBinding) {
        BinaryMessenger messenger = flutterPluginBinding.getBinaryMessenger();
        channel = new MethodChannel(messenger, "certificate_pinning_httpclient",
                StandardMethodCodec.INSTANCE, messenger.makeBackgroundTaskQueue());
        channel.setMethodCallHandler(this);
    }

    @Override
    public void onMethodCall(@NonNull MethodCall call, @NonNull Result result) {
        if (call.method.equals("fetchHostCertificates")) {
            try {
                final URL url = new URL(call.argument("url"));
                HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
                connection.setConnectTimeout(FETCH_CERTIFICATES_TIMEOUT_MS);
                connection.connect();
                Certificate[] certificates = connection.getServerCertificates();

                final List<byte[]> hostCertificates = new ArrayList<>(certificates.length);

                for (Certificate certificate : certificates) {
                    hostCertificates.add(certificate.getEncoded());
                }

                connection.disconnect();

                addRootExplicitlyIfNeeded(certificates, hostCertificates);

                result.success(hostCertificates);
            } catch (Exception e) {
                result.error("fetchHostCertificates", e.getLocalizedMessage(), null);
            }
        } else {
            result.notImplemented();
        }
    }

    /**
     * Add the root certificate explicitly if it is not already in the server's chain
     * @param certificates The server's certificate chain
     * @param hostCertificates The list of public keys against which the client can pin
     * @throws CertificateEncodingException If the certificate encoding fails
     */
    private void addRootExplicitlyIfNeeded(Certificate[] certificates, List<byte[]> hostCertificates) throws CertificateEncodingException {
        final X509Certificate[] acceptedIssuers = getAcceptedIssuers();

        // Get the last certificate in the server's chain
        X509Certificate lastServerCertificate = (X509Certificate) certificates[certificates.length - 1];

        boolean lastCertIsAcceptedRoot = isAcceptedCert(acceptedIssuers, lastServerCertificate);

        if (!lastCertIsAcceptedRoot) {
            X509Certificate rootCertificate = findIssuer(acceptedIssuers, lastServerCertificate);

            // If a matching root certificate was found, add its encoded value to the hostCertificates list
            if (rootCertificate != null) {
                hostCertificates.add(rootCertificate.getEncoded());
            }
        }
    }

    private X509Certificate[] getAcceptedIssuers() {
        try {
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init((KeyStore) null);
            TrustManager[] trustManagers = tmf.getTrustManagers();

            // Check if we have a single X509TrustManager
            if (trustManagers.length != 1 || !(trustManagers[0] instanceof X509TrustManager)) {
                throw new IllegalStateException("Unexpected default trust managers: " + Arrays.toString(trustManagers));
            }

            X509TrustManager trustManager = (X509TrustManager) trustManagers[0];
            return trustManager.getAcceptedIssuers();
        } catch (Exception e) {
            // Handle error
            Log.e("CertificatePinning", "Error getting accepted issuers: " + e.getMessage());
        }

        return new X509Certificate[0];
    }

    private boolean isAcceptedCert(X509Certificate[] acceptedIssuers, X509Certificate targetCert) {
        for (X509Certificate issuer : acceptedIssuers) {
            if (issuer.getSubjectX500Principal().equals(targetCert.getSubjectX500Principal())
                && issuer.getPublicKey().equals(targetCert.getPublicKey())) {
                return true;
            }
        }

        return false;
    }

    private X509Certificate findIssuer(X509Certificate[] acceptedIssuers, X509Certificate targetCert) {
        for (X509Certificate issuer : acceptedIssuers) {
            if (issuer.getSubjectX500Principal().equals(targetCert.getIssuerX500Principal())) {
                try {
                    targetCert.verify(issuer.getPublicKey());
                    return issuer;
                } catch (Exception e) {
                    Log.e("CertificatePinning", "The certificate was not signed by the root CS found in trust store: " + e.getMessage());
                }
            }
        }

        return null;
    }

    @Override
    public void onDetachedFromEngine(@NonNull FlutterPluginBinding binding) {
        channel.setMethodCallHandler(null);
    }
}
