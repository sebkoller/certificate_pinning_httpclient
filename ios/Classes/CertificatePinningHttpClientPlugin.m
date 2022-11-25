/**
* Copyright 2022 CriticalBlue Ltd.
*
* Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
* associated documentation files (the "Software"), to deal in the Software without restriction,
* including without limitation the rights to use, copy, modify, merge, publish, distribute,
* sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all copies or
* substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
* NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
* NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
* DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT
* OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#import "CertificatePinningHttpClientPlugin.h"


// Definition for a special class to fetch host certificates by implementing a NSURLSessionTaskDelegate that
// is called upon initial connection to get the certificates but the connection is dropped at that point.
@interface HostCertificatesFetcher: NSObject<NSURLSessionTaskDelegate>

// Host certificates for the current connection
@property NSArray<FlutterStandardTypedData *> *hostCertificates;

// Get the host certificates for an URL
- (NSArray<FlutterStandardTypedData *> *)fetchCertificates:(NSURL *)url;

@end


// Timeout in seconds for a getting the host certificates
static const NSTimeInterval FETCH_CERTIFICATES_TIMEOUT = 3;

// CertificatePinningHttpClientPlugin provides the bridge to the Approov SDK itself. Methods are initiated using the
// MethodChannel to call various methods within the SDK. A facility is also provided to probe the certificates
// presented on any particular URL to implement the pinning. Note that the MethodChannel must run on a background
// thread since it makes blocking calls.
@implementation CertificatePinningHttpClientPlugin

+ (void)registerWithRegistrar:(NSObject<FlutterPluginRegistrar>*)registrar {
    NSObject<FlutterTaskQueue>* taskQueue = [[registrar messenger] makeBackgroundTaskQueue];
    FlutterMethodChannel* channel = [[FlutterMethodChannel alloc]
                 initWithName: @"certificate_pinning_httpclient"
              binaryMessenger: [registrar messenger]
                        codec: [FlutterStandardMethodCodec sharedInstance]
                    taskQueue: taskQueue];
    CertificatePinningHttpClientPlugin* instance = [[CertificatePinningHttpClientPlugin alloc] init];
    [registrar addMethodCallDelegate:instance channel:channel];
}


- (void)handleMethodCall:(FlutterMethodCall *)call result:(FlutterResult)result {
    if ([@"fetchHostCertificates" isEqualToString:call.method]) {
        NSURL *url = [NSURL URLWithString:call.arguments[@"url"]];
        if (url == nil) {
            result([FlutterError errorWithCode:[NSString stringWithFormat:@"%d", -1]
                message:NSURLErrorDomain
                details:[NSString stringWithFormat:@"Fetch host certificates invalid URL: %@", call.arguments[@"url"]]]);
        } else {
            HostCertificatesFetcher *hostCertificatesFetcher = [[HostCertificatesFetcher alloc] init];
            NSArray<FlutterStandardTypedData *> *hostCerts = [hostCertificatesFetcher fetchCertificates:url];
            result(hostCerts);
        }
    } else {
        result(FlutterMethodNotImplemented);
    }
}

@end

// Implementation of the HostCertificatesFetcher which obtains certificate chains for part particular domains in order to implement the pinning.
@implementation HostCertificatesFetcher

// Fetches the certificates for a host by setting up an HTTPS GET request and harvesting the certificates
- (NSArray<FlutterStandardTypedData *> *)fetchCertificates:(NSURL *)url
{
    // There are no certtificates initially
    _hostCertificates = nil;

    // Create the Session
    NSURLSessionConfiguration *sessionConfig = [NSURLSessionConfiguration ephemeralSessionConfiguration];
    sessionConfig.timeoutIntervalForResource = FETCH_CERTIFICATES_TIMEOUT;
    NSURLSession* URLSession = [NSURLSession sessionWithConfiguration:sessionConfig delegate:self delegateQueue:nil];

    // Create the request
    NSMutableURLRequest *certFetchRequest = [NSMutableURLRequest requestWithURL:url];
    [certFetchRequest setTimeoutInterval:FETCH_CERTIFICATES_TIMEOUT];
    [certFetchRequest setHTTPMethod:@"GET"];

    // Set up a semaphore so we can detect when the request completed
    dispatch_semaphore_t certFetchComplete = dispatch_semaphore_create(0);

    // Get session task to issue the request, write back any error on completion and signal the semaphore
    // to indicate that it is complete
    __block NSError *certFetchError = nil;
    NSURLSessionTask *certFetchTask = [URLSession dataTaskWithRequest:certFetchRequest
        completionHandler:^(NSData *data, NSURLResponse *response, NSError *error)
        {
            certFetchError = error;
            dispatch_semaphore_signal(certFetchComplete);
        }];

    // Make the request
    [certFetchTask resume];

    // Wait on the semaphore which shows when the network request is completed - note we do not use
    // a timeout here since the NSURLSessionTask has its own timeouts
    dispatch_semaphore_wait(certFetchComplete, DISPATCH_TIME_FOREVER);

    // We expect error cancelled because URLSession:task:didReceiveChallenge:completionHandler: always deliberately
    // fails the challenge because we don't need the request to succeed to retrieve the certificates
    if (!certFetchError) {
        // If no error occurred, the certificate check of the NSURLSessionTaskDelegate protocol has not been called.
        //  Don't return any host certificates
        NSLog(@"Failed to get host certificates: Error: unknown\n");
        return nil;
    }
    if (certFetchError && (certFetchError.code != NSURLErrorCancelled)) {
        // If an error other than NSURLErrorCancelled occurred, don't return any host certificates
        NSLog(@"Failed to get host certificates: Error: %@\n", certFetchError.localizedDescription);
        return nil;
    }

    // The host certificates have been collected by the URLSession:task:didReceiveChallenge:completionHandler:
    // method below
    return _hostCertificates;
}

// Collect the host certificates using the certificate check of the NSURLSessionTaskDelegate protocol
- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task
    didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
    completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential * _Nullable))completionHandler
{
    // Ignore any requests that are not related to server trust
    if (![challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust])
        return;

    // Check we have a server trust
    SecTrustRef serverTrust = challenge.protectionSpace.serverTrust;
    if (!serverTrust) {
        completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
        return;
    }

    // Check the validity of the server trust
    SecTrustResultType result;
    OSStatus aStatus = SecTrustEvaluate(serverTrust, &result);
    if (errSecSuccess != aStatus) {
        completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
        return;
    }

    // Collect all the certs in the chain
    CFIndex certCount = SecTrustGetCertificateCount(serverTrust);
    NSMutableArray<FlutterStandardTypedData *> *certs = [NSMutableArray arrayWithCapacity:(NSUInteger)certCount];
    for (int certIndex = 0; certIndex < certCount; certIndex++) {
        // get the chain certificate
        SecCertificateRef cert = SecTrustGetCertificateAtIndex(serverTrust, certIndex);
        if (!cert) {
            completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
            return;
        }
        NSData *certData = (NSData *) CFBridgingRelease(SecCertificateCopyData(cert));
        FlutterStandardTypedData *certFSTD = [FlutterStandardTypedData typedDataWithBytes:certData];
        [certs addObject:certFSTD];
    }

    // Set the host certs to be returned from fetchCertificates
    _hostCertificates = certs;

    // Fail the challenge as we only wanted the certificates
    completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
}

@end
