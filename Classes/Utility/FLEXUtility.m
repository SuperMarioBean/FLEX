//
//  FLEXUtility.m
//  Flipboard
//
//  Created by Ryan Olson on 4/18/14.
//  Copyright (c) 2020 FLEX Team. All rights reserved.
//

#import "FLEXColor.h"
#import "FLEXUtility.h"
#import "FLEXResources.h"
#import "FLEXWindow.h"
#import <ImageIO/ImageIO.h>
#import <objc/runtime.h>
#import <zlib.h>
#include <CommonCrypto/CommonCrypto.h>
#include <zlib.h>

/**
 Provide hash, encrypt, encode and some common method for `NSData`.
 */
@interface NSData (FMTAdd)

/**
 Returns an NSString for base64 encoded.
 */
- (nullable NSString *)base64EncodedString;

/**
 Returns an NSData from base64 encoded string.
 
 @warning This method has been implemented in iOS7.
 
 @param base64EncodedString  The encoded string.
 */
+ (nullable NSData *)dataWithBase64EncodedString:(NSString *)base64EncodedString;

#pragma mark - Encrypt and Decrypt
///=============================================================================
/// @name Encrypt and Decrypt
///=============================================================================

/**
 Returns an encrypted NSData using AES.
 
 @param key   A key length of 16, 24 or 32 (128, 192 or 256bits).
 
 @param iv    An initialization vector length of 16(128bits).
              Pass nil when you don't want to use iv.
 
 @return      An NSData encrypted, or nil if an error occurs.
 */
- (nullable NSData *)aes256EncryptWithKey:(NSData *)key iv:(nullable NSData *)iv;

/**
 Returns an decrypted NSData using AES.
 
 @param key   A key length of 16, 24 or 32 (128, 192 or 256bits).
 
 @param iv    An initialization vector length of 16(128bits).
              Pass nil when you don't want to use iv.
 
 @return      An NSData decrypted, or nil if an error occurs.
 */
- (nullable NSData *)aes256DecryptWithkey:(NSData *)key iv:(nullable NSData *)iv;

@end

@implementation NSData (YYAdd)

static const char base64EncodingTable[64]
= "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const short base64DecodingTable[256] = {
    -2, -2, -2, -2, -2, -2, -2, -2, -2, -1, -1, -2,  -1,  -1, -2, -2,
    -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,  -2,  -2, -2, -2,
    -1, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, 62,  -2,  -2, -2, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -2, -2,  -2,  -2, -2, -2,
    -2, 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10,  11,  12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -2,  -2,  -2, -2, -2,
    -2, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36,  37,  38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -2,  -2,  -2, -2, -2,
    -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,  -2,  -2, -2, -2,
    -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,  -2,  -2, -2, -2,
    -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,  -2,  -2, -2, -2,
    -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,  -2,  -2, -2, -2,
    -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,  -2,  -2, -2, -2,
    -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,  -2,  -2, -2, -2,
    -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,  -2,  -2, -2, -2,
    -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,  -2,  -2, -2, -2
};

- (NSString *)base64EncodedString {
    NSUInteger length = self.length;
    if (length == 0)
        return @"";
    
    NSUInteger out_length = ((length + 2) / 3) * 4;
    uint8_t *output = malloc(((out_length + 2) / 3) * 4);
    if (output == NULL)
        return nil;
    
    const char *input = self.bytes;
    NSInteger i, value;
    for (i = 0; i < length; i += 3) {
        value = 0;
        for (NSInteger j = i; j < i + 3; j++) {
            value <<= 8;
            if (j < length) {
                value |= (0xFF & input[j]);
            }
        }
        NSInteger index = (i / 3) * 4;
        output[index + 0] = base64EncodingTable[(value >> 18) & 0x3F];
        output[index + 1] = base64EncodingTable[(value >> 12) & 0x3F];
        output[index + 2] = ((i + 1) < length)
        ? base64EncodingTable[(value >> 6) & 0x3F]
        : '=';
        output[index + 3] = ((i + 2) < length)
        ? base64EncodingTable[(value >> 0) & 0x3F]
        : '=';
    }
    
    NSString *base64 = [[NSString alloc] initWithBytes:output
                                                length:out_length
                                              encoding:NSASCIIStringEncoding];
    free(output);
    return base64;
}

+ (NSData *)dataWithBase64EncodedString:(NSString *)base64EncodedString {
    NSInteger length = base64EncodedString.length;
    const char *string = [base64EncodedString cStringUsingEncoding:NSASCIIStringEncoding];
    if (string  == NULL)
        return nil;
    
    while (length > 0 && string[length - 1] == '=')
        length--;
    
    NSInteger outputLength = length * 3 / 4;
    NSMutableData *data = [NSMutableData dataWithLength:outputLength];
    if (data == nil)
        return nil;
    if (length == 0)
        return data;
    
    uint8_t *output = data.mutableBytes;
    NSInteger inputPoint = 0;
    NSInteger outputPoint = 0;
    while (inputPoint < length) {
        char i0 = string[inputPoint++];
        char i1 = string[inputPoint++];
        char i2 = inputPoint < length ? string[inputPoint++] : 'A';
        char i3 = inputPoint < length ? string[inputPoint++] : 'A';
        
        output[outputPoint++] = (base64DecodingTable[i0] << 2)
        | (base64DecodingTable[i1] >> 4);
        if (outputPoint < outputLength) {
            output[outputPoint++] = ((base64DecodingTable[i1] & 0xf) << 4)
            | (base64DecodingTable[i2] >> 2);
        }
        if (outputPoint < outputLength) {
            output[outputPoint++] = ((base64DecodingTable[i2] & 0x3) << 6)
            | base64DecodingTable[i3];
        }
    }
    
    return data;
}


- (NSData *)aes256EncryptWithKey:(NSData *)key iv:(NSData *)iv {
    if (key.length != 16 && key.length != 24 && key.length != 32) {
        return nil;
    }
    if (iv.length != 16 && iv.length != 0) {
        return nil;
    }
    
    NSData *result = nil;
    size_t bufferSize = self.length + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    if (!buffer) return nil;
    size_t encryptedSize = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt,
                                          kCCAlgorithmAES128,
                                          kCCOptionPKCS7Padding,
                                          key.bytes,
                                          key.length,
                                          iv.bytes,
                                          self.bytes,
                                          self.length,
                                          buffer,
                                          bufferSize,
                                          &encryptedSize);
    if (cryptStatus == kCCSuccess) {
        result = [[NSData alloc]initWithBytes:buffer length:encryptedSize];
        free(buffer);
        return result;
    } else {
        free(buffer);
        return nil;
    }
}

- (NSData *)aes256DecryptWithkey:(NSData *)key iv:(NSData *)iv {
    if (key.length != 16 && key.length != 24 && key.length != 32) {
        return nil;
    }
    if (iv.length != 16 && iv.length != 0) {
        return nil;
    }
    
    NSData *result = nil;
    size_t bufferSize = self.length + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    if (!buffer) return nil;
    size_t encryptedSize = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt,
                                          kCCAlgorithmAES128,
                                          kCCOptionPKCS7Padding,
                                          key.bytes,
                                          key.length,
                                          iv.bytes,
                                          self.bytes,
                                          self.length,
                                          buffer,
                                          bufferSize,
                                          &encryptedSize);
    if (cryptStatus == kCCSuccess) {
        result = [[NSData alloc]initWithBytes:buffer length:encryptedSize];
        free(buffer);
        return result;
    } else {
        free(buffer);
        return nil;
    }
}

@end

BOOL FLEXConstructorsShouldRun() {
    #if FLEX_DISABLE_CTORS
        return NO;
    #else
        static BOOL _FLEXConstructorsShouldRun_storage = YES;
        
        static dispatch_once_t onceToken;
        dispatch_once(&onceToken, ^{
            NSString *key = @"FLEX_SKIP_INIT";
            if (getenv(key.UTF8String) || [NSUserDefaults.standardUserDefaults boolForKey:key]) {
                _FLEXConstructorsShouldRun_storage = NO;
            }
        });
        
        return _FLEXConstructorsShouldRun_storage;
    #endif
}

@implementation FLEXUtility

+ (UIWindow *)appKeyWindow {
    // First, check UIApplication.keyWindow
    FLEXWindow *window = (id)UIApplication.sharedApplication.keyWindow;
    if (window) {
        if ([window isKindOfClass:[FLEXWindow class]]) {
            return window.previousKeyWindow;
        }
        
        return window;
    }
    
    // As of iOS 13, UIApplication.keyWindow does not return nil,
    // so this is more of a safeguard against it returning nil in the future.
    //
    // Also, these are obviously not all FLEXWindows; FLEXWindow is used
    // so we can call window.previousKeyWindow without an ugly cast
    for (FLEXWindow *window in UIApplication.sharedApplication.windows) {
        if (window.isKeyWindow) {
            if ([window isKindOfClass:[FLEXWindow class]]) {
                return window.previousKeyWindow;
            }
            
            return window;
        }
    }
    
    return nil;
}

+ (UIWindowScene *)activeScene {
    for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
        // Look for an active UIWindowScene
        if (scene.activationState == UISceneActivationStateForegroundActive &&
            [scene isKindOfClass:[UIWindowScene class]]) {
            return (UIWindowScene *)scene;
        }
    }
    
    return nil;
}

+ (UIViewController *)topViewControllerInWindow:(UIWindow *)window {
    UIViewController *topViewController = window.rootViewController;
    while (topViewController.presentedViewController) {
        topViewController = topViewController.presentedViewController;
    }
    return topViewController;
}

+ (UIColor *)consistentRandomColorForObject:(id)object {
    CGFloat hue = (((NSUInteger)object >> 4) % 256) / 255.0;
    return [UIColor colorWithHue:hue saturation:1.0 brightness:1.0 alpha:1.0];
}

+ (NSString *)descriptionForView:(UIView *)view includingFrame:(BOOL)includeFrame {
    NSString *description = [[view class] description];
    
    NSString *viewControllerDescription = [[[self viewControllerForView:view] class] description];
    if (viewControllerDescription.length > 0) {
        description = [description stringByAppendingFormat:@" (%@)", viewControllerDescription];
    }
    
    if (includeFrame) {
        description = [description stringByAppendingFormat:@" %@", [self stringForCGRect:view.frame]];
    }
    
    if (view.accessibilityLabel.length > 0) {
        description = [description stringByAppendingFormat:@" · %@", view.accessibilityLabel];
    }
    
    return description;
}

+ (NSString *)stringForCGRect:(CGRect)rect {
    return [NSString stringWithFormat:@"{(%g, %g), (%g, %g)}",
        rect.origin.x, rect.origin.y, rect.size.width, rect.size.height
    ];
}

+ (UIViewController *)viewControllerForView:(UIView *)view {
    NSString *viewDelegate = @"_viewDelegate";
    if ([view respondsToSelector:NSSelectorFromString(viewDelegate)]) {
        return [view valueForKey:viewDelegate];
    }

    return nil;
}

+ (UIViewController *)viewControllerForAncestralView:(UIView *)view {
    NSString *_viewControllerForAncestor = @"_viewControllerForAncestor";
    if ([view respondsToSelector:NSSelectorFromString(_viewControllerForAncestor)]) {
        return [view valueForKey:_viewControllerForAncestor];
    }

    return nil;
}

+ (UIImage *)previewImageForView:(UIView *)view {
    if (CGRectIsEmpty(view.bounds)) {
        return [UIImage new];
    }
    
    CGSize viewSize = view.bounds.size;
    UIGraphicsBeginImageContextWithOptions(viewSize, NO, 0.0);
    [view drawViewHierarchyInRect:CGRectMake(0, 0, viewSize.width, viewSize.height) afterScreenUpdates:YES];
    UIImage *previewImage = UIGraphicsGetImageFromCurrentImageContext();
    UIGraphicsEndImageContext();
    return previewImage;
}

+ (UIImage *)previewImageForLayer:(CALayer *)layer {
    if (CGRectIsEmpty(layer.bounds)) {
        return nil;
    }
    
    UIGraphicsBeginImageContextWithOptions(layer.bounds.size, NO, 0.0);
    CGContextRef imageContext = UIGraphicsGetCurrentContext();
    [layer renderInContext:imageContext];
    UIImage *previewImage = UIGraphicsGetImageFromCurrentImageContext();
    UIGraphicsEndImageContext();
    return previewImage;
}

+ (NSString *)detailDescriptionForView:(UIView *)view {
    return [NSString stringWithFormat:@"frame %@", [self stringForCGRect:view.frame]];
}

+ (UIImage *)circularImageWithColor:(UIColor *)color radius:(CGFloat)radius {
    CGFloat diameter = radius * 2.0;
    UIGraphicsBeginImageContextWithOptions(CGSizeMake(diameter, diameter), NO, 0.0);
    CGContextRef imageContext = UIGraphicsGetCurrentContext();
    CGContextSetFillColorWithColor(imageContext, color.CGColor);
    CGContextFillEllipseInRect(imageContext, CGRectMake(0, 0, diameter, diameter));
    UIImage *circularImage = UIGraphicsGetImageFromCurrentImageContext();
    UIGraphicsEndImageContext();
    return circularImage;
}

+ (UIColor *)hierarchyIndentPatternColor {
    static UIColor *patternColor = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        UIImage *indentationPatternImage = FLEXResources.hierarchyIndentPattern;
        patternColor = [UIColor colorWithPatternImage:indentationPatternImage];
        if (@available(iOS 13.0, *)) {
            // Create a dark mode version
            UIGraphicsBeginImageContextWithOptions(
                indentationPatternImage.size, NO, indentationPatternImage.scale
            );
            [FLEXColor.iconColor set];
            [indentationPatternImage drawInRect:CGRectMake(
                0, 0, indentationPatternImage.size.width, indentationPatternImage.size.height
            )];
            UIImage *darkModePatternImage = UIGraphicsGetImageFromCurrentImageContext();
            UIGraphicsEndImageContext();

            // Create dynamic color provider
            patternColor = [UIColor colorWithDynamicProvider:^UIColor *(UITraitCollection *traitCollection) {
                return (traitCollection.userInterfaceStyle == UIUserInterfaceStyleLight
                        ? [UIColor colorWithPatternImage:indentationPatternImage]
                        : [UIColor colorWithPatternImage:darkModePatternImage]);
            }];
        }
    });

    return patternColor;
}

+ (NSString *)applicationImageName {
    return NSBundle.mainBundle.executablePath;
}

+ (NSString *)applicationName {
    return FLEXUtility.applicationImageName.lastPathComponent;
}

+ (NSString *)pointerToString:(void *)ptr {
    return [NSString stringWithFormat:@"%p", ptr];
}

+ (NSString *)addressOfObject:(id)object {
    return [NSString stringWithFormat:@"%p", object];
}

+ (NSString *)stringByEscapingHTMLEntitiesInString:(NSString *)originalString {
    static NSDictionary<NSString *, NSString *> *escapingDictionary = nil;
    static NSRegularExpression *regex = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        escapingDictionary = @{ @" " : @"&nbsp;",
                                @">" : @"&gt;",
                                @"<" : @"&lt;",
                                @"&" : @"&amp;",
                                @"'" : @"&apos;",
                                @"\"" : @"&quot;",
                                @"«" : @"&laquo;",
                                @"»" : @"&raquo;"
                                };
        regex = [NSRegularExpression regularExpressionWithPattern:@"(&|>|<|'|\"|«|»)" options:0 error:NULL];
    });
    
    NSMutableString *mutableString = originalString.mutableCopy;
    
    NSArray<NSTextCheckingResult *> *matches = [regex
        matchesInString:mutableString options:0 range:NSMakeRange(0, mutableString.length)
    ];
    for (NSTextCheckingResult *result in matches.reverseObjectEnumerator) {
        NSString *foundString = [mutableString substringWithRange:result.range];
        NSString *replacementString = escapingDictionary[foundString];
        if (replacementString) {
            [mutableString replaceCharactersInRange:result.range withString:replacementString];
        }
    }
    
    return [mutableString copy];
}

+ (UIInterfaceOrientationMask)infoPlistSupportedInterfaceOrientationsMask {
    NSArray<NSString *> *supportedOrientations = NSBundle.mainBundle.infoDictionary[@"UISupportedInterfaceOrientations"];
    UIInterfaceOrientationMask supportedOrientationsMask = 0;
    if ([supportedOrientations containsObject:@"UIInterfaceOrientationPortrait"]) {
        supportedOrientationsMask |= UIInterfaceOrientationMaskPortrait;
    }
    if ([supportedOrientations containsObject:@"UIInterfaceOrientationMaskLandscapeRight"]) {
        supportedOrientationsMask |= UIInterfaceOrientationMaskLandscapeRight;
    }
    if ([supportedOrientations containsObject:@"UIInterfaceOrientationMaskPortraitUpsideDown"]) {
        supportedOrientationsMask |= UIInterfaceOrientationMaskPortraitUpsideDown;
    }
    if ([supportedOrientations containsObject:@"UIInterfaceOrientationLandscapeLeft"]) {
        supportedOrientationsMask |= UIInterfaceOrientationMaskLandscapeLeft;
    }
    return supportedOrientationsMask;
}

+ (UIImage *)thumbnailedImageWithMaxPixelDimension:(NSInteger)dimension fromImageData:(NSData *)data {
    UIImage *thumbnail = nil;
    CGImageSourceRef imageSource = CGImageSourceCreateWithData((__bridge CFDataRef)data, 0);
    if (imageSource) {
        NSDictionary<NSString *, id> *options = @{
            (__bridge id)kCGImageSourceCreateThumbnailWithTransform : @YES,
            (__bridge id)kCGImageSourceCreateThumbnailFromImageAlways : @YES,
            (__bridge id)kCGImageSourceThumbnailMaxPixelSize : @(dimension)
        };

        CGImageRef scaledImageRef = CGImageSourceCreateThumbnailAtIndex(
            imageSource, 0, (__bridge CFDictionaryRef)options
        );
        if (scaledImageRef) {
            thumbnail = [UIImage imageWithCGImage:scaledImageRef];
            CFRelease(scaledImageRef);
        }
        CFRelease(imageSource);
    }
    return thumbnail;
}

+ (NSString *)stringFromRequestDuration:(NSTimeInterval)duration {
    NSString *string = @"0s";
    if (duration > 0.0) {
        if (duration < 1.0) {
            string = [NSString stringWithFormat:@"%dms", (int)(duration * 1000)];
        } else if (duration < 10.0) {
            string = [NSString stringWithFormat:@"%.2fs", duration];
        } else {
            string = [NSString stringWithFormat:@"%.1fs", duration];
        }
    }
    return string;
}

+ (NSString *)statusCodeStringFromURLResponse:(NSURLResponse *)response {
    NSString *httpResponseString = nil;
    if ([response isKindOfClass:[NSHTTPURLResponse class]]) {
        NSHTTPURLResponse *httpResponse = (NSHTTPURLResponse *)response;
        NSString *statusCodeDescription = nil;
        if (httpResponse.statusCode == 200) {
            // Prefer OK to the default "no error"
            statusCodeDescription = @"OK";
        } else {
            statusCodeDescription = [NSHTTPURLResponse localizedStringForStatusCode:httpResponse.statusCode];
        }
        httpResponseString = [NSString stringWithFormat:@"%ld %@", (long)httpResponse.statusCode, statusCodeDescription];
    }
    return httpResponseString;
}

+ (BOOL)isErrorStatusCodeFromURLResponse:(NSURLResponse *)response {
    if ([response isKindOfClass:[NSHTTPURLResponse class]]) {
        NSHTTPURLResponse *httpResponse = (NSHTTPURLResponse *)response;
        return httpResponse.statusCode >= 400;
    }
    
    return NO;
}

+ (NSArray<NSURLQueryItem *> *)itemsFromQueryString:(NSString *)query request:(NSURLRequest *)request {
    NSMutableArray<NSURLQueryItem *> *items = [NSMutableArray new];

    // [a=1, b=2, c=3]
    NSArray<NSString *> *queryComponents = [query componentsSeparatedByString:@"&"];
    for (NSString *keyValueString in queryComponents) {
        // [a, 1]
        NSArray<NSString *> *components = [keyValueString componentsSeparatedByString:@"="];
        if (components.count == 2) {
            NSString *key = components.firstObject.stringByRemovingPercentEncoding;
            NSString *value = components.lastObject.stringByRemovingPercentEncoding;
            
            NSString *host = request.URL.host;
            if ([host hasSuffix:@"pixelplanettech.com"]) {
                if ([key isEqualToString:@"request"]) {
                    // decretyped request field
                    NSString *encrypedString = value;
                    NSData *key = nil;
                    NSData *vi = nil;
                    id o = nil;
                    
                    if ([host isEqualToString:@"account.pixelplanettech.com"]) {
                        NSData *key = [@"sd0GS9vQVDeL6grX" dataUsingEncoding:NSUTF8StringEncoding];
                        NSData *iv = [@"r8owYuCDekUXWxyU" dataUsingEncoding:NSUTF8StringEncoding];
                        NSData *e = [[NSData dataWithBase64EncodedString:encrypedString] aes256DecryptWithkey:key iv:iv];
                        o = [NSJSONSerialization JSONObjectWithData:e options:0 error:NULL];
                    } else if ([host isEqualToString:@"page.pixelplanettech.com"]) {
                        NSData *key = [@"ABmlagLrKFaE6ypc" dataUsingEncoding:NSUTF8StringEncoding];
                        NSData *iv = [@"ILvc4mhfKaoiAe8L" dataUsingEncoding:NSUTF8StringEncoding];
                        NSData *e = [[NSData dataWithBase64EncodedString:encrypedString] aes256DecryptWithkey:key iv:iv];
                        o = [NSJSONSerialization JSONObjectWithData:e options:0 error:NULL];
                    } else if ([host isEqualToString:@"pay.pixelplanettech.com"]) {
                        NSData *key = [@"sd0GS9vQVDeL6grX" dataUsingEncoding:NSUTF8StringEncoding];
                        NSData *iv = [@"r8owYuCDekUXWxyU" dataUsingEncoding:NSUTF8StringEncoding];
                        NSData *e = [[NSData dataWithBase64EncodedString:encrypedString] aes256DecryptWithkey:key iv:iv];
                        o = [NSJSONSerialization JSONObjectWithData:e options:0 error:NULL];
                    } else if ([host isEqualToString:@"mall.pixelplanettech.com"]) {
                        NSData *key = [@"JvGeHqzMqkAwa4L1" dataUsingEncoding:NSUTF8StringEncoding];
                        NSData *iv = [@"x1wpMEhFljxQs898" dataUsingEncoding:NSUTF8StringEncoding];
                        NSData *e = [[NSData dataWithBase64EncodedString:encrypedString] aes256DecryptWithkey:key iv:iv];
                        o = [NSJSONSerialization JSONObjectWithData:e options:0 error:NULL];
                    } else {
                        // do nothing
                    }
                    
                    // Thanks RaziPour1993
                    value = [[NSString alloc] initWithData:[NSJSONSerialization dataWithJSONObject:o
                                                                                           options:NSJSONWritingPrettyPrinted
                                                                                             error:NULL]
                                                  encoding:NSUTF8StringEncoding];
                    // NSJSONSerialization escapes forward slashes.
                    // We want pretty json, so run through and unescape the slashes.prettyJSONStringFromData
                    value = [value stringByReplacingOccurrencesOfString:@"\\/" withString:@"/"];
                } else if ([key isEqualToString:@"cmdId"]) {
                    // convert cmdId to 0x
                    [items addObject:[NSURLQueryItem queryItemWithName:@"cmdId(hex)"
                                                                 value:[NSString stringWithFormat:@"0x%2X", value.integerValue]]];
                }
            }
            
            [items addObject:[NSURLQueryItem queryItemWithName:key value:value]];
        }
    }

    return items.copy;
}

+ (NSString *)prettyJSONStringFromData:(NSData *)data response:(NSURLResponse *)response {
    NSString *prettyString = nil;
    
    id jsonObject = [NSJSONSerialization JSONObjectWithData:data options:0 error:NULL];
    if ([NSJSONSerialization isValidJSONObject:jsonObject]) {
        NSString *host = response.URL.host;
        if ([host hasSuffix:@"pixelplanettech.com"]) {
            NSString *encrypedString = nil;
            NSData *key = nil;
            NSData *vi = nil;
            id o = nil;
            
            // decrypted
            if ([host isEqualToString:@"account.pixelplanettech.com"]) {
                NSString *encrypedString = jsonObject[@"response"];
                NSData *key = [@"sd0GS9vQVDeL6grX" dataUsingEncoding:NSUTF8StringEncoding];
                NSData *iv = [@"r8owYuCDekUXWxyU" dataUsingEncoding:NSUTF8StringEncoding];
                NSData *e = [[NSData dataWithBase64EncodedString:encrypedString] aes256DecryptWithkey:key iv:iv];
                o = [NSJSONSerialization JSONObjectWithData:e options:0 error:NULL];
                NSMutableDictionary *d = [NSMutableDictionary dictionaryWithDictionary:jsonObject];
                d[@"response"] = o;
                jsonObject = [d copy];
            } else if ([host isEqualToString:@"page.pixelplanettech.com"]) {
                NSString *encrypedString = jsonObject[@"response"];
                NSData *key = [@"ABmlagLrKFaE6ypc" dataUsingEncoding:NSUTF8StringEncoding];
                NSData *iv = [@"ILvc4mhfKaoiAe8L" dataUsingEncoding:NSUTF8StringEncoding];
                NSData *e = [[NSData dataWithBase64EncodedString:encrypedString] aes256DecryptWithkey:key iv:iv];
                o = [NSJSONSerialization JSONObjectWithData:e options:0 error:NULL];
                NSMutableDictionary *d = [NSMutableDictionary dictionaryWithDictionary:jsonObject];
                d[@"response"] = o;
                jsonObject = [d copy];
            } else if ([host isEqualToString:@"pay.pixelplanettech.com"]) {
                NSString *encrypedString = jsonObject[@"response"];
                NSData *key = [@"sd0GS9vQVDeL6grX" dataUsingEncoding:NSUTF8StringEncoding];
                NSData *iv = [@"r8owYuCDekUXWxyU" dataUsingEncoding:NSUTF8StringEncoding];
                NSData *e = [[NSData dataWithBase64EncodedString:encrypedString] aes256DecryptWithkey:key iv:iv];
                o = [NSJSONSerialization JSONObjectWithData:e options:0 error:NULL];
                NSMutableDictionary *d = [NSMutableDictionary dictionaryWithDictionary:jsonObject];
                d[@"response"] = o;
                jsonObject = [d copy];
            } else if ([host isEqualToString:@"mall.pixelplanettech.com"]) {
                NSString *encrypedString = jsonObject[@"response"];
                NSData *key = [@"JvGeHqzMqkAwa4L1" dataUsingEncoding:NSUTF8StringEncoding];
                NSData *iv = [@"x1wpMEhFljxQs898" dataUsingEncoding:NSUTF8StringEncoding];
                NSData *e = [[NSData dataWithBase64EncodedString:encrypedString] aes256DecryptWithkey:key iv:iv];
                o = [NSJSONSerialization JSONObjectWithData:e options:0 error:NULL];
                NSMutableDictionary *d = [NSMutableDictionary dictionaryWithDictionary:jsonObject];
                d[@"response"] = o;
                jsonObject = [d copy];
            } else {
                // do nothing
            }
        }
        
        // Thanks RaziPour1993
        prettyString = [[NSString alloc]
            initWithData:[NSJSONSerialization
                dataWithJSONObject:jsonObject options:NSJSONWritingPrettyPrinted error:NULL
            ]
            encoding:NSUTF8StringEncoding
        ];
        // NSJSONSerialization escapes forward slashes.
        // We want pretty json, so run through and unescape the slashes.prettyJSONStringFromData
        prettyString = [prettyString stringByReplacingOccurrencesOfString:@"\\/" withString:@"/"];
    } else {
        prettyString = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    }
    
    return prettyString;
}

+ (BOOL)isValidJSONData:(NSData *)data {
    return [NSJSONSerialization JSONObjectWithData:data options:0 error:NULL] ? YES : NO;
}

// Thanks to the following links for help with this method
// https://www.cocoanetics.com/2012/02/decompressing-files-into-memory/
// https://github.com/nicklockwood/GZIP
+ (NSData *)inflatedDataFromCompressedData:(NSData *)compressedData {
    NSData *inflatedData = nil;
    NSUInteger compressedDataLength = compressedData.length;
    if (compressedDataLength > 0) {
        z_stream stream;
        stream.zalloc = Z_NULL;
        stream.zfree = Z_NULL;
        stream.avail_in = (uInt)compressedDataLength;
        stream.next_in = (void *)compressedData.bytes;
        stream.total_out = 0;
        stream.avail_out = 0;

        NSMutableData *mutableData = [NSMutableData dataWithLength:compressedDataLength * 1.5];
        if (inflateInit2(&stream, 15 + 32) == Z_OK) {
            int status = Z_OK;
            while (status == Z_OK) {
                if (stream.total_out >= mutableData.length) {
                    mutableData.length += compressedDataLength / 2;
                }
                stream.next_out = (uint8_t *)[mutableData mutableBytes] + stream.total_out;
                stream.avail_out = (uInt)(mutableData.length - stream.total_out);
                status = inflate(&stream, Z_SYNC_FLUSH);
            }
            if (inflateEnd(&stream) == Z_OK) {
                if (status == Z_STREAM_END) {
                    mutableData.length = stream.total_out;
                    inflatedData = [mutableData copy];
                }
            }
        }
    }
    return inflatedData;
}

+ (NSArray<UIWindow *> *)allWindows {
    BOOL includeInternalWindows = YES;
    BOOL onlyVisibleWindows = NO;

    // Obfuscating selector allWindowsIncludingInternalWindows:onlyVisibleWindows:
    NSArray<NSString *> *allWindowsComponents = @[
        @"al", @"lWindo", @"wsIncl", @"udingInt", @"ernalWin", @"dows:o", @"nlyVisi", @"bleWin", @"dows:"
    ];
    SEL allWindowsSelector = NSSelectorFromString([allWindowsComponents componentsJoinedByString:@""]);

    NSMethodSignature *methodSignature = [[UIWindow class] methodSignatureForSelector:allWindowsSelector];
    NSInvocation *invocation = [NSInvocation invocationWithMethodSignature:methodSignature];

    invocation.target = [UIWindow class];
    invocation.selector = allWindowsSelector;
    [invocation setArgument:&includeInternalWindows atIndex:2];
    [invocation setArgument:&onlyVisibleWindows atIndex:3];
    [invocation invoke];

    __unsafe_unretained NSArray<UIWindow *> *windows = nil;
    [invocation getReturnValue:&windows];
    return windows;
}

+ (UIAlertController *)alert:(NSString *)title message:(NSString *)message {
    return [UIAlertController
        alertControllerWithTitle:title
        message:message
        preferredStyle:UIAlertControllerStyleAlert
    ];
}

+ (SEL)swizzledSelectorForSelector:(SEL)selector {
    return NSSelectorFromString([NSString stringWithFormat:
        @"_flex_swizzle_%x_%@", arc4random(), NSStringFromSelector(selector)
    ]);
}

+ (BOOL)instanceRespondsButDoesNotImplementSelector:(SEL)selector class:(Class)cls {
    if ([cls instancesRespondToSelector:selector]) {
        unsigned int numMethods = 0;
        Method *methods = class_copyMethodList(cls, &numMethods);
        
        BOOL implementsSelector = NO;
        for (int index = 0; index < numMethods; index++) {
            SEL methodSelector = method_getName(methods[index]);
            if (selector == methodSelector) {
                implementsSelector = YES;
                break;
            }
        }
        
        free(methods);
        
        if (!implementsSelector) {
            return YES;
        }
    }
    
    return NO;
}

+ (void)replaceImplementationOfKnownSelector:(SEL)originalSelector
                                     onClass:(Class)class
                                   withBlock:(id)block
                            swizzledSelector:(SEL)swizzledSelector {
    // This method is only intended for swizzling methods that are know to exist on the class.
    // Bail if that isn't the case.
    Method originalMethod = class_getInstanceMethod(class, originalSelector);
    if (!originalMethod) {
        return;
    }
    
    IMP implementation = imp_implementationWithBlock(block);
    class_addMethod(class, swizzledSelector, implementation, method_getTypeEncoding(originalMethod));
    Method newMethod = class_getInstanceMethod(class, swizzledSelector);
    method_exchangeImplementations(originalMethod, newMethod);
}

+ (void)replaceImplementationOfSelector:(SEL)selector
                           withSelector:(SEL)swizzledSelector
                               forClass:(Class)cls
                  withMethodDescription:(struct objc_method_description)methodDescription
                    implementationBlock:(id)implementationBlock undefinedBlock:(id)undefinedBlock {
    if ([self instanceRespondsButDoesNotImplementSelector:selector class:cls]) {
        return;
    }
    
    IMP implementation = imp_implementationWithBlock((id)(
        [cls instancesRespondToSelector:selector] ? implementationBlock : undefinedBlock)
    );
    
    Method oldMethod = class_getInstanceMethod(cls, selector);
    const char *types = methodDescription.types;
    if (oldMethod) {
        if (!types) {
            types = method_getTypeEncoding(oldMethod);
        }

        class_addMethod(cls, swizzledSelector, implementation, types);
        Method newMethod = class_getInstanceMethod(cls, swizzledSelector);
        method_exchangeImplementations(oldMethod, newMethod);
    } else {
        if (!types) {
            // Some protocol method descriptions don't have .types populated
            // Set the return type to void and ignore arguments
            types = "v@:";
        }
        class_addMethod(cls, selector, implementation, types);
    }
}

@end
