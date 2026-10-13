// Standalone experimental qualification host. No wallet or governance integration.
#import <UIKit/UIKit.h>
#import <mach/mach.h>
#import <sys/utsname.h>

extern int parliament_qualification_run(const char *path, unsigned samples, const char *row);

@interface QualificationDelegate : UIResponder <UIApplicationDelegate>
@property(nonatomic, strong) UIWindow *window;
@property(nonatomic, strong) UILabel *label;
@property(nonatomic, strong) NSTimer *timer;
@property(nonatomic, strong) NSString *directory;
@property(nonatomic, strong) NSMutableArray *observations;
@property(nonatomic, strong) NSDate *started;
@property(nonatomic, strong) NSString *runLabel;
@property(nonatomic, assign) unsigned samples;
@property(nonatomic, strong) NSString *row;
@end

@implementation QualificationDelegate
- (NSDictionary *)observation {
    task_vm_info_data_t info = {0};
    mach_msg_type_number_t count = TASK_VM_INFO_COUNT;
    kern_return_t result = task_info(mach_task_self(), TASK_VM_INFO, (task_info_t)&info, &count);
    UIDevice *device = UIDevice.currentDevice;
    return @{
        @"elapsed_seconds": @(-[self.started timeIntervalSinceNow]),
        @"thermal_state": @(NSProcessInfo.processInfo.thermalState),
        @"low_power_mode": @(NSProcessInfo.processInfo.lowPowerModeEnabled),
        @"battery_state": @(device.batteryState),
        @"battery_level": @(device.batteryLevel),
        @"task_info_success": @(result == KERN_SUCCESS),
        @"physical_footprint_bytes": @(result == KERN_SUCCESS ? info.phys_footprint : 0),
        @"resident_bytes": @(result == KERN_SUCCESS ? info.resident_size : 0)
    };
}

- (void)sample {
    [self.observations addObject:[self observation]];
    self.label.text = [NSString stringWithFormat:
        @"Parliament B6\n\nExperimental • Production gated\n\n%@\n%u samples per case\n%.0f seconds elapsed\n\nPublic test credentials only.\nKeep this app in the foreground.",
        self.runLabel, self.samples, -[self.started timeIntervalSinceNow]];
}

- (void)runBenchmark {
    @autoreleasepool {
        NSString *path = [self.directory stringByAppendingPathComponent:@"measurements.ndjson"];
        int result = parliament_qualification_run(path.fileSystemRepresentation, self.samples, self.row.UTF8String);
        dispatch_async(dispatch_get_main_queue(), ^{
            [self sample];
            [self.timer invalidate];
            self.timer = nil;
            struct utsname system;
            uname(&system);
            NSDictionary *metadata = @{
                @"run_label": self.runLabel,
                @"result_code": @(result),
                @"model_identifier": @(system.machine),
                @"os_version": UIDevice.currentDevice.systemVersion,
                @"kernel_release": @(system.release),
                @"physical_memory_bytes": @(NSProcessInfo.processInfo.physicalMemory),
                @"active_processor_count": @(NSProcessInfo.processInfo.activeProcessorCount),
                @"observation_interval_seconds": @0.25,
                @"worker_stack_reservation_bytes": @(8 * 1024 * 1024),
                @"started_utc": self.started,
                @"finished_utc": NSDate.date,
                @"observations": self.observations,
                @"production_gated": @YES,
                @"baseline_qualified": @NO
            };
            BOOL saved = [metadata writeToFile:[self.directory stringByAppendingPathComponent:@"device.plist"] atomically:YES];
            NSString *status = [NSString stringWithFormat:@"result=%d\nmetadata_saved=%d\n", result, saved];
            [status writeToFile:[self.directory stringByAppendingPathComponent:@"complete.txt"] atomically:YES encoding:NSUTF8StringEncoding error:nil];
            self.label.text = [NSString stringWithFormat:@"Parliament B6\n\n%@\n\n%@\n\nProduction remains gated.", self.runLabel,
                result == 0 && saved ? @"Measurement complete" : @"Measurement failed — retain diagnostic files"];
            UIApplication.sharedApplication.idleTimerDisabled = NO;
        });
    }
}

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    (void)launchOptions;
    NSArray<NSString *> *arguments = NSProcessInfo.processInfo.arguments;
    self.runLabel = @"manual";
    self.samples = 31;
    self.row = @"candidate";
    for (NSUInteger i = 1; i + 1 < arguments.count; i++) {
        if ([arguments[i] isEqualToString:@"--run-label"]) self.runLabel = arguments[++i];
        else if ([arguments[i] isEqualToString:@"--samples"]) self.samples = (unsigned)[arguments[++i] integerValue];
        else if ([arguments[i] isEqualToString:@"--row"]) self.row = arguments[++i];
    }
    NSCharacterSet *allowed = [NSCharacterSet characterSetWithCharactersInString:@"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"];
    if (self.runLabel.length == 0 || [self.runLabel rangeOfCharacterFromSet:allowed.invertedSet].location != NSNotFound || self.samples < 1 || self.samples > 1001) return NO;
    self.directory = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject stringByAppendingPathComponent:self.runLabel];
    if ([NSFileManager.defaultManager fileExistsAtPath:self.directory]) return NO;
    NSError *error = nil;
    if (![NSFileManager.defaultManager createDirectoryAtPath:self.directory withIntermediateDirectories:YES attributes:nil error:&error]) return NO;
    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    UIViewController *controller = UIViewController.new;
    controller.view.backgroundColor = UIColor.systemBackgroundColor;
    self.label = [[UILabel alloc] initWithFrame:CGRectInset(self.window.bounds, 24, 60)];
    self.label.numberOfLines = 0;
    self.label.textAlignment = NSTextAlignmentCenter;
    self.label.textColor = UIColor.labelColor;
    self.label.font = [UIFont systemFontOfSize:20];
    [controller.view addSubview:self.label];
    self.window.rootViewController = controller;
    [self.window makeKeyAndVisible];
    UIDevice.currentDevice.batteryMonitoringEnabled = YES;
    application.idleTimerDisabled = YES;
    self.started = NSDate.date;
    self.observations = NSMutableArray.new;
    [self sample];
    self.timer = [NSTimer scheduledTimerWithTimeInterval:0.25 target:self selector:@selector(sample) userInfo:nil repeats:YES];
    NSThread *worker = [[NSThread alloc] initWithTarget:self selector:@selector(runBenchmark) object:nil];
    worker.name = @"Parliament qualification";
    worker.stackSize = 8 * 1024 * 1024;
    worker.qualityOfService = NSQualityOfServiceUserInitiated;
    [worker start];
    return YES;
}
@end

int main(int argc, char *argv[]) {
    @autoreleasepool { return UIApplicationMain(argc, argv, nil, NSStringFromClass(QualificationDelegate.class)); }
}
