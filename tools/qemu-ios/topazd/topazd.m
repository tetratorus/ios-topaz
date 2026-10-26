/*
 * topazd - guest agent for the ios-topaz phone/QEMU guest.
 *
 * A plain-HTTP server on 0.0.0.0:7777, run as root by launchd from
 * /Library/LaunchDaemons/org.sweet.topazd.plist. It installs, registers,
 * launches, kills and lists /Applications bundles without ever shelling out
 * (the root filesystem has no /bin/sh).
 *
 * The LaunchServices registration follows Procursus uicache (uikittools-ng):
 * -[LSApplicationWorkspace registerApplicationDictionary:] with an
 * ApplicationType of System, the bundle's own entitlements and an
 * MCMAppDataContainer. The private classes are declared here and reached with
 * NSClassFromString after dlopen, so no private SDK stubs are needed.
 */
#import <Foundation/Foundation.h>
#import <mach-o/loader.h>
#import <mach-o/fat.h>
#import <arpa/inet.h>
#import <netinet/in.h>
#import <netinet/tcp.h>
#import <sys/socket.h>
#import <sys/stat.h>
#import <sys/mount.h>
#import <dlfcn.h>
#import <errno.h>
#import <signal.h>
#import <unistd.h>

/* ---- things the iOS SDK does not declare ---- */

int proc_listallpids(void *buffer, int buffersize);
int proc_pidpath(int pid, void *buffer, uint32_t buffersize);
int renamex_np(const char *from, const char *to, unsigned int flags);
#ifndef RENAME_SWAP
#define RENAME_SWAP 0x0002
#endif
#define PROC_PIDPATHINFO_MAXSIZE (4 * MAXPATHLEN)

#ifndef APPS_DIR
#define APPS_DIR @"/Applications"
#endif
#ifndef STAGING_DIR
#define STAGING_DIR @"/var/tmp"
#endif

@interface LSApplicationProxy : NSObject
+ (instancetype)applicationProxyForIdentifier:(NSString *)identifier;
- (NSString *)bundleIdentifier;
- (NSString *)applicationIdentifier;
- (NSURL *)bundleURL;
- (NSString *)applicationType;
- (NSString *)bundleExecutable;
- (NSString *)canonicalExecutablePath;
- (id)localizedNameForContext:(id)context;
@end

@interface LSApplicationWorkspace : NSObject
+ (instancetype)defaultWorkspace;
- (BOOL)registerApplicationDictionary:(NSDictionary *)dict;
- (BOOL)registerApplication:(NSURL *)url;
- (BOOL)unregisterApplication:(NSURL *)url;
- (BOOL)openApplicationWithBundleID:(NSString *)bundleID;
- (BOOL)openSensitiveURL:(NSURL *)url withOptions:(NSDictionary *)options;
- (BOOL)openURL:(NSURL *)url;
- (NSArray<LSApplicationProxy *> *)allInstalledApplications;
- (NSArray<LSApplicationProxy *> *)allApplications;
@end

@interface MCMContainer : NSObject
+ (instancetype)containerWithIdentifier:(NSString *)identifier
                      createIfNecessary:(BOOL)create
                                existed:(BOOL *)existed
                                  error:(NSError **)error;
- (NSURL *)url;
@end

typedef NS_OPTIONS(NSUInteger, SBSRelaunchActionOptions) {
	SBSRelaunchActionOptionsNone = 0,
	SBSRelaunchActionOptionsRestartRenderServer = 1 << 0,
	SBSRelaunchActionOptionsSnapshotTransition = 1 << 1,
	SBSRelaunchActionOptionsFadeToBlackTransition = 1 << 2
};

@interface SBSRelaunchAction : NSObject
+ (instancetype)actionWithReason:(NSString *)reason
                         options:(SBSRelaunchActionOptions)options
                       targetURL:(NSURL *)targetURL;
@end

@interface FBSSystemService : NSObject
+ (instancetype)sharedService;
- (void)sendActions:(NSSet *)actions withResult:(id)result;
- (void)openApplication:(NSString *)bundleID
                options:(NSDictionary *)options
             withResult:(void (^)(NSError *error))result;
- (int)pidForApplication:(NSString *)bundleID;
@end

/* ---- logging ---- */

static void
tlog(NSString *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
	va_end(ap);

	static NSDateFormatter *df;
	if (df == nil) {
		df = [NSDateFormatter new];
		df.dateFormat = @"yyyy-MM-dd HH:mm:ss";
		df.timeZone = [NSTimeZone timeZoneWithName:@"UTC"];
	}
	printf("%s topazd: %s\n", [df stringFromDate:[NSDate date]].UTF8String, msg.UTF8String);
	fflush(stdout);
}

/* ---- private frameworks ---- */

static void *gFrontBoard;

static void
load_private_frameworks(void)
{
	gFrontBoard = dlopen("/System/Library/PrivateFrameworks/FrontBoardServices.framework/FrontBoardServices", RTLD_NOW);
	if (gFrontBoard == NULL) {
		tlog(@"warning: FrontBoardServices: %s", dlerror());
	}
	if (dlopen("/System/Library/PrivateFrameworks/SpringBoardServices.framework/SpringBoardServices", RTLD_NOW) == NULL) {
		tlog(@"warning: SpringBoardServices: %s", dlerror());
	}
	if (dlopen("/System/Library/PrivateFrameworks/MobileContainerManager.framework/MobileContainerManager", RTLD_NOW) == NULL) {
		tlog(@"warning: MobileContainerManager: %s", dlerror());
	}
}

static NSString *
fbs_unlock_option_key(void)
{
	NSString *__strong *key = (NSString * __strong *)dlsym(gFrontBoard, "FBSOpenApplicationOptionKeyUnlockDevice");
	return key != NULL && *key != nil ? *key : @"__UnlockDevice";
}

static LSApplicationWorkspace *
workspace(void)
{
	return (LSApplicationWorkspace *)[NSClassFromString(@"LSApplicationWorkspace") defaultWorkspace];
}

/* ---- embedded entitlements, read straight out of the code signature ---- */

#define CSMAGIC_EMBEDDED_SIGNATURE      0xfade0cc0u
#define CSMAGIC_EMBEDDED_ENTITLEMENTS   0xfade7171u

static NSDictionary *
entitlements_of_binary(NSString *path)
{
	NSData *bin = [NSData dataWithContentsOfFile:path options:NSDataReadingMappedIfSafe error:nil];
	if (bin == nil || bin.length < sizeof(struct mach_header_64)) {
		return nil;
	}
	const uint8_t *base = bin.bytes;
	size_t total = bin.length;
	size_t slice = 0;

	uint32_t magic = *(const uint32_t *)base;
	if (magic == FAT_CIGAM || magic == FAT_MAGIC) {
		const struct fat_header *fh = (const struct fat_header *)base;
		uint32_t n = OSSwapBigToHostInt32(fh->nfat_arch);
		if (sizeof(*fh) + n * sizeof(struct fat_arch) > total) {
			return nil;
		}
		const struct fat_arch *fa = (const struct fat_arch *)(base + sizeof(*fh));
		for (uint32_t i = 0; i < n; i++) {
			if (OSSwapBigToHostInt32(fa[i].cputype) == CPU_TYPE_ARM64) {
				slice = OSSwapBigToHostInt32(fa[i].offset);
				break;
			}
		}
		if (slice == 0 || slice + sizeof(struct mach_header_64) > total) {
			return nil;
		}
		magic = *(const uint32_t *)(base + slice);
	}
	if (magic != MH_MAGIC_64) {
		return nil;
	}
	const struct mach_header_64 *mh = (const struct mach_header_64 *)(base + slice);
	const uint8_t *cmds = (const uint8_t *)(mh + 1);
	uint32_t sigoff = 0, sigsize = 0;

	for (uint32_t i = 0; i < mh->ncmds; i++) {
		const struct load_command *lc = (const struct load_command *)cmds;
		if (lc->cmdsize < sizeof(*lc) || (const uint8_t *)lc + lc->cmdsize > base + total) {
			return nil;
		}
		if (lc->cmd == LC_CODE_SIGNATURE) {
			const struct linkedit_data_command *ld = (const struct linkedit_data_command *)lc;
			sigoff = ld->dataoff;
			sigsize = ld->datasize;
			break;
		}
		cmds += lc->cmdsize;
	}
	if (sigsize < 12 || slice + sigoff + sigsize > total) {
		return nil;
	}

	const uint8_t *sig = base + slice + sigoff;
	if (OSSwapBigToHostInt32(*(const uint32_t *)sig) != CSMAGIC_EMBEDDED_SIGNATURE) {
		return nil;
	}
	uint32_t count = OSSwapBigToHostInt32(*(const uint32_t *)(sig + 8));
	if (12 + count * 8u > sigsize) {
		return nil;
	}
	for (uint32_t i = 0; i < count; i++) {
		uint32_t off = OSSwapBigToHostInt32(*(const uint32_t *)(sig + 12 + i * 8 + 4));
		if (off + 8 > sigsize) {
			continue;
		}
		uint32_t bmagic = OSSwapBigToHostInt32(*(const uint32_t *)(sig + off));
		uint32_t blen = OSSwapBigToHostInt32(*(const uint32_t *)(sig + off + 4));
		if (bmagic != CSMAGIC_EMBEDDED_ENTITLEMENTS || blen < 8 || off + blen > sigsize) {
			continue;
		}
		NSData *plist = [NSData dataWithBytes:sig + off + 8 length:blen - 8];
		id ents = [NSPropertyListSerialization propertyListWithData:plist options:0 format:NULL error:nil];
		return [ents isKindOfClass:[NSDictionary class]] ? ents : nil;
	}
	return nil;
}

/* ---- tar (ustar/GNU/pax), extracted by hand: no /bin/sh, no libarchive ---- */

struct tar_hdr {
	char name[100], mode[8], uid[8], gid[8], size[12], mtime[12], chksum[8];
	char typeflag, linkname[100], magic[6], version[2];
	char uname[32], gname[32], devmajor[8], devminor[8], prefix[155], pad[12];
};

static unsigned long long
tar_octal(const char *field, size_t len)
{
	/* GNU base-256 for large values, otherwise octal with any padding. */
	if ((field[0] & 0x80) != 0) {
		unsigned long long v = field[0] & 0x7f;
		for (size_t i = 1; i < len; i++) {
			v = (v << 8) | (unsigned char)field[i];
		}
		return v;
	}
	unsigned long long v = 0;
	for (size_t i = 0; i < len; i++) {
		char c = field[i];
		if (c >= '0' && c <= '7') {
			v = v * 8 + (unsigned)(c - '0');
		} else if (c != ' ' && c != '\0') {
			break;
		} else if (v != 0) {
			break;
		}
	}
	return v;
}

/* A path is only allowed to stay inside the destination. */
static BOOL
tar_path_safe(NSString *name)
{
	if (name.length == 0 || [name hasPrefix:@"/"]) {
		return NO;
	}
	for (NSString *part in [name pathComponents]) {
		if ([part isEqualToString:@".."]) {
			return NO;
		}
	}
	return YES;
}

static void
pax_paths(NSData *record, NSString **path, NSString **linkpath)
{
	/* "<len> key=value\n" records; only path and linkpath matter here. */
	NSString *text = [[NSString alloc] initWithData:record encoding:NSUTF8StringEncoding];

	for (NSString *line in [text componentsSeparatedByString:@"\n"]) {
		NSRange sp = [line rangeOfString:@" "];
		if (sp.location == NSNotFound) {
			continue;
		}
		NSString *kv = [line substringFromIndex:sp.location + 1];
		NSRange eq = [kv rangeOfString:@"="];
		if (eq.location == NSNotFound) {
			continue;
		}
		NSString *key = [kv substringToIndex:eq.location];
		if ([key isEqualToString:@"path"]) {
			*path = [kv substringFromIndex:eq.location + 1];
		} else if ([key isEqualToString:@"linkpath"]) {
			*linkpath = [kv substringFromIndex:eq.location + 1];
		}
	}
}

/* The parent directory must still be inside dest after resolving symlinks. */
static BOOL
tar_parent_inside(NSString *out, NSString *realDest)
{
	char real[PATH_MAX];
	NSString *parent = [out stringByDeletingLastPathComponent];

	if (realpath(parent.fileSystemRepresentation, real) == NULL) {
		return NO;
	}
	NSString *r = [NSString stringWithUTF8String:real];
	return [r isEqualToString:realDest] || [r hasPrefix:[realDest stringByAppendingString:@"/"]];
}

static BOOL
tar_extract(NSData *tar, NSString *dest, NSString **errOut)
{
	NSFileManager *fm = [NSFileManager defaultManager];
	const uint8_t *p = tar.bytes;
	size_t len = tar.length, off = 0;
	NSString *override = nil;       /* from a GNU 'L' or pax 'x' record */
	NSString *link_override = nil;
	NSMutableArray *dir_modes = [NSMutableArray array];
	char realbuf[PATH_MAX];

	if (realpath(dest.fileSystemRepresentation, realbuf) == NULL) {
		*errOut = [NSString stringWithFormat:@"realpath %@: %s", dest, strerror(errno)];
		return NO;
	}
	NSString *realDest = [NSString stringWithUTF8String:realbuf];

	while (off + 512 <= len) {
		const struct tar_hdr *h = (const struct tar_hdr *)(p + off);
		if (h->name[0] == '\0') {
			BOOL zero = YES;
			for (size_t i = 0; i < 512; i++) {
				if (p[off + i] != 0) {
					zero = NO;
					break;
				}
			}
			if (zero) {
				break;          /* end-of-archive */
			}
		}
		off += 512;

		unsigned long long size = tar_octal(h->size, sizeof(h->size));
		size_t padded = (size_t)((size + 511) / 512 * 512);
		if (off + size > len) {
			*errOut = @"truncated tar";
			return NO;
		}

		char namebuf[256];
		snprintf(namebuf, sizeof(namebuf), "%.155s%s%.100s", h->prefix,
		    h->prefix[0] != '\0' ? "/" : "", h->name);
		NSString *name = override ?: [NSString stringWithUTF8String:namebuf];
		char type = h->typeflag;

		if (type == 'L' || type == 'x' || type == 'X') {
			NSData *rec = [NSData dataWithBytes:p + off length:(NSUInteger)size];
			if (type == 'L') {
				override = [[NSString alloc] initWithData:rec encoding:NSUTF8StringEncoding];
				override = [override stringByTrimmingCharactersInSet:
				    [NSCharacterSet characterSetWithCharactersInString:@"\0\n"]];
			} else {
				NSString *path = nil, *linkpath = nil;
				pax_paths(rec, &path, &linkpath);
				if (path != nil) {
					override = path;
				}
				if (linkpath != nil) {
					link_override = linkpath;
				}
			}
			off += padded;
			continue;
		}
		if (type == 'K') {
			NSData *rec = [NSData dataWithBytes:p + off length:(NSUInteger)size];
			link_override = [[[NSString alloc] initWithData:rec encoding:NSUTF8StringEncoding]
			    stringByTrimmingCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@"\0\n"]];
			off += padded;
			continue;
		}
		override = nil;

		name = [name stringByTrimmingCharactersInSet:
		    [NSCharacterSet characterSetWithCharactersInString:@"\0"]];
		if (!tar_path_safe(name)) {
			*errOut = [NSString stringWithFormat:@"unsafe path in tar: %@", name];
			return NO;
		}
		NSString *out = [dest stringByAppendingPathComponent:name];
		[fm createDirectoryAtPath:[out stringByDeletingLastPathComponent]
		    withIntermediateDirectories:YES attributes:nil error:nil];
		if (!tar_parent_inside(out, realDest)) {
			*errOut = [NSString stringWithFormat:@"tar entry %@ escapes the bundle through a symlink", name];
			return NO;
		}
		mode_t mode = (mode_t)(tar_octal(h->mode, sizeof(h->mode)) & 07777);

		if (type == '5' || [name hasSuffix:@"/"]) {
			if (![fm createDirectoryAtPath:out withIntermediateDirectories:YES
			        attributes:@{NSFilePosixPermissions: @(mode ?: 0755)} error:nil]) {
				*errOut = [NSString stringWithFormat:@"mkdir %@ failed", out];
				return NO;
			}
			[dir_modes addObject:@[out, @(mode ?: 0755)]];
		} else if (type == '0' || type == '\0' || type == '7') {
			[fm createDirectoryAtPath:[out stringByDeletingLastPathComponent]
			    withIntermediateDirectories:YES attributes:nil error:nil];
			NSData *body = [NSData dataWithBytes:p + off length:(NSUInteger)size];
			if (![body writeToFile:out options:NSDataWritingAtomic error:nil]) {
				*errOut = [NSString stringWithFormat:@"write %@ failed", out];
				return NO;
			}
			chmod(out.fileSystemRepresentation, mode ?: 0644);
		} else if (type == '2') {
			NSString *target = link_override ?:
			    [NSString stringWithFormat:@"%.100s", h->linkname];
			[fm createDirectoryAtPath:[out stringByDeletingLastPathComponent]
			    withIntermediateDirectories:YES attributes:nil error:nil];
			unlink(out.fileSystemRepresentation);
			if (symlink(target.UTF8String, out.fileSystemRepresentation) != 0) {
				*errOut = [NSString stringWithFormat:@"symlink %@ failed: %s", out, strerror(errno)];
				return NO;
			}
		} else if (type == '1') {
			NSString *target = link_override ?:
			    [NSString stringWithFormat:@"%.100s", h->linkname];
			if (tar_path_safe(target)) {
				unlink(out.fileSystemRepresentation);
				link([dest stringByAppendingPathComponent:target].fileSystemRepresentation,
				    out.fileSystemRepresentation);
			}
		}
		/* anything else (fifo, device, 'g' global header) is skipped */
		link_override = nil;
		off += padded;
	}

	/* Directory modes last: extracting into them may have needed +w. */
	for (NSArray *dm in dir_modes.reverseObjectEnumerator) {
		chmod([dm[0] fileSystemRepresentation], (mode_t)[dm[1] unsignedIntValue]);
	}
	return YES;
}

/* ---- ownership: launchd runs us as root, the bundle must be root:wheel ---- */

static void
chown_recursively(NSString *path)
{
	NSFileManager *fm = [NSFileManager defaultManager];
	lchown(path.fileSystemRepresentation, 0, 0);
	for (NSString *sub in [fm subpathsOfDirectoryAtPath:path error:nil]) {
		lchown([path stringByAppendingPathComponent:sub].fileSystemRepresentation, 0, 0);
	}
}

/* ---- LaunchServices registration, the way uicache does it ---- */

static NSDictionary *
group_containers(NSDictionary *ents, BOOL system)
{
	NSString *key = system ? @"com.apple.security.system-groups" : @"com.apple.security.application-groups";
	Class cls = NSClassFromString(system ? @"MCMSystemDataContainer" : @"MCMSharedDataContainer");
	NSArray *ids = ents[key];

	if (cls == nil || ![ids isKindOfClass:[NSArray class]]) {
		return nil;
	}
	NSMutableDictionary *out = [NSMutableDictionary dictionary];
	for (NSString *gid in ids) {
		MCMContainer *c = [cls containerWithIdentifier:gid createIfNecessary:YES existed:nil error:nil];
		if (c.url.path != nil) {
			out[gid] = c.url.path;
		}
	}
	return out.count != 0 ? out.copy : nil;
}

static BOOL
register_bundle(NSString *appPath, NSString **bundleIDOut, NSString **errOut)
{
	appPath = appPath.stringByResolvingSymlinksInPath.stringByStandardizingPath;
	NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:
	    [appPath stringByAppendingPathComponent:@"Info.plist"]];
	NSString *bundleID = info[@"CFBundleIdentifier"];

	if (bundleID == nil) {
		*errOut = [NSString stringWithFormat:@"no CFBundleIdentifier in %@/Info.plist", appPath];
		return NO;
	}
	*bundleIDOut = bundleID;

	NSString *exec = [appPath stringByAppendingPathComponent:info[@"CFBundleExecutable"] ?: @""];
	NSDictionary *ents = entitlements_of_binary(exec);
	NSNumber *noContainer = ents[@"com.apple.private.security.no-container"];
	BOOL containerized = !([noContainer isKindOfClass:[NSNumber class]] && noContainer.boolValue);

	NSString *containerPath = nil;
	Class mcm = NSClassFromString(@"MCMAppDataContainer");
	if (mcm != nil) {
		MCMContainer *c = [mcm containerWithIdentifier:bundleID createIfNecessary:YES existed:nil error:nil];
		containerPath = c.url.path;
	}

	NSMutableDictionary *d = [NSMutableDictionary dictionary];
	if (ents != nil) {
		d[@"Entitlements"] = ents;
	}
	d[@"ApplicationType"] = @"System";
	d[@"BundleNameIsLocalized"] = @1;
	d[@"CFBundleIdentifier"] = bundleID;
	d[@"CodeInfoIdentifier"] = bundleID;
	d[@"CompatibilityState"] = @0;
	d[@"IsContainerized"] = @(containerized);
	if (containerPath != nil) {
		d[@"Container"] = containerPath;
		d[@"EnvironmentVariables"] = @{
			@"CFFIXED_USER_HOME": containerized ? containerPath : @"/var/mobile",
			@"HOME": containerized ? containerPath : @"/var/mobile",
			@"TMPDIR": containerized ? [containerPath stringByAppendingPathComponent:@"tmp"] : @"/var/tmp",
		};
	}
	d[@"IsDeletable"] = @NO;
	d[@"Path"] = appPath;
	d[@"SignerOrganization"] = @"Apple Inc.";
	d[@"SignatureVersion"] = @132352;
	d[@"SignerIdentity"] = @"Apple iPhone OS Application Signing";
	d[@"IsAdHocSigned"] = @YES;
	d[@"LSInstallType"] = @1;
	d[@"HasMIDBasedSINF"] = @0;
	d[@"MissingSINF"] = @0;
	d[@"FamilyID"] = @0;
	d[@"IsOnDemandInstallCapable"] = @0;
	d[@"_LSBundlePlugins"] = @{};
	NSString *team = ents[@"com.apple.developer.team-identifier"];
	if ([team isKindOfClass:[NSString class]]) {
		d[@"TeamIdentifier"] = team;
	}
	NSDictionary *appGroups = group_containers(ents, NO);
	NSDictionary *sysGroups = group_containers(ents, YES);
	if (appGroups.count != 0 || sysGroups.count != 0) {
		NSMutableDictionary *all = [NSMutableDictionary dictionary];
		[all addEntriesFromDictionary:appGroups];
		[all addEntriesFromDictionary:sysGroups];
		if (appGroups.count != 0) {
			d[@"HasAppGroupContainers"] = @YES;
		}
		if (sysGroups.count != 0) {
			d[@"HasSystemGroupContainers"] = @YES;
		}
		d[@"GroupContainers"] = all.copy;
	}

	LSApplicationWorkspace *ws = workspace();
	if ([ws registerApplicationDictionary:d]) {
		tlog(@"registered %@ at %@ (entitlements: %lu keys, container %@)", bundleID, appPath,
		    (unsigned long)ents.count, containerPath ?: @"none");
		return YES;
	}
	tlog(@"registerApplicationDictionary: failed for %@, falling back to registerApplication:", bundleID);
	if ([ws respondsToSelector:@selector(registerApplication:)] &&
	    [ws registerApplication:[NSURL fileURLWithPath:appPath isDirectory:YES]]) {
		tlog(@"registerApplication: succeeded for %@", bundleID);
		return YES;
	}
	*errOut = [NSString stringWithFormat:@"could not register %@ with LaunchServices", appPath];
	return NO;
}

static void
respring(void)
{
	Class actionCls = NSClassFromString(@"SBSRelaunchAction");
	Class serviceCls = NSClassFromString(@"FBSSystemService");

	if (actionCls == nil || serviceCls == nil) {
		tlog(@"respring unavailable (SBSRelaunchAction/FBSSystemService missing)");
		return;
	}
	SBSRelaunchAction *action = [actionCls actionWithReason:@"topazd"
	    options:(SBSRelaunchActionOptionsRestartRenderServer | SBSRelaunchActionOptionsFadeToBlackTransition)
	    targetURL:nil];
	tlog(@"respringing SpringBoard");
	[(FBSSystemService *)[serviceCls sharedService] sendActions:[NSSet setWithObject:action] withResult:nil];
}

/* ---- processes ---- */

static NSArray<NSNumber *> *
pids_under_path(NSString *prefix)
{
	int n = proc_listallpids(NULL, 0);
	if (n <= 0) {
		return @[];
	}
	size_t bytes = (size_t)(n + 64) * sizeof(pid_t);
	pid_t *pids = malloc(bytes);
	NSMutableArray *out = [NSMutableArray array];

	if (pids == NULL) {
		return @[];
	}
	n = proc_listallpids(pids, (int)bytes);
	for (int i = 0; i < n; i++) {
		char path[PROC_PIDPATHINFO_MAXSIZE];
		if (pids[i] <= 1 || proc_pidpath(pids[i], path, sizeof(path)) <= 0) {
			continue;
		}
		if ([[NSString stringWithUTF8String:path] hasPrefix:prefix]) {
			[out addObject:@(pids[i])];
		}
	}
	free(pids);
	return out;
}

static LSApplicationProxy *
proxy_for_bundle(NSString *bundleID)
{
	LSApplicationProxy *p = [NSClassFromString(@"LSApplicationProxy") applicationProxyForIdentifier:bundleID];
	if (p.bundleURL != nil) {
		return p;
	}
	for (LSApplicationProxy *app in [workspace() allInstalledApplications]) {
		if ([app.bundleIdentifier isEqualToString:bundleID]) {
			return app;
		}
	}
	return nil;
}

/* ---- HTTP ---- */

struct reply {
	int status;
	NSString *type;
	NSData *body;
};

static struct reply
reply_text(int status, NSString *text)
{
	return (struct reply){status, @"text/plain; charset=utf-8",
		       [[text stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding]};
}

static struct reply
reply_json(int status, id object)
{
	NSData *json = [NSJSONSerialization dataWithJSONObject:object
	    options:NSJSONWritingPrettyPrinted error:nil];
	return (struct reply){status, @"application/json", json};
}

static NSString *
percent_decode(NSString *s)
{
	return [s stringByRemovingPercentEncoding] ?: s;
}

static NSDictionary *
parse_query(NSString *query)
{
	NSMutableDictionary *out = [NSMutableDictionary dictionary];

	for (NSString *pair in [query componentsSeparatedByString:@"&"]) {
		NSRange eq = [pair rangeOfString:@"="];
		if (eq.location == NSNotFound) {
			if (pair.length != 0) {
				out[percent_decode(pair)] = @"";
			}
			continue;
		}
		out[percent_decode([pair substringToIndex:eq.location])] =
		    percent_decode([pair substringFromIndex:eq.location + 1]);
	}
	return out;
}

/* ---- endpoints ---- */

static struct reply
ep_install(NSData *body, NSDictionary *query)
{
	NSFileManager *fm = [NSFileManager defaultManager];
	NSString *err = nil;

	if (body.length < 512) {
		return reply_text(500, @"error: POST /install needs a tar body");
	}
	NSString *tmp = [NSString stringWithFormat:@"%@/topazd-%u-%u", STAGING_DIR, getpid(), arc4random()];
	if (![fm createDirectoryAtPath:tmp withIntermediateDirectories:YES attributes:nil error:nil]) {
		return reply_text(500, [NSString stringWithFormat:@"error: cannot create %@", tmp]);
	}
	if (!tar_extract(body, tmp, &err)) {
		[fm removeItemAtPath:tmp error:nil];
		return reply_text(500, [NSString stringWithFormat:@"error: %@", err]);
	}

	NSString *appName = nil;
	for (NSString *entry in [fm contentsOfDirectoryAtPath:tmp error:nil]) {
		if ([entry.pathExtension isEqualToString:@"app"]) {
			appName = entry;
			break;
		}
	}
	if (appName == nil) {
		[fm removeItemAtPath:tmp error:nil];
		return reply_text(500, @"error: no top-level *.app in the tar");
	}
	NSString *staged = [tmp stringByAppendingPathComponent:appName];
	NSString *target = [APPS_DIR stringByAppendingPathComponent:appName];

	NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:
	    [staged stringByAppendingPathComponent:@"Info.plist"]];
	if (info[@"CFBundleIdentifier"] == nil) {
		[fm removeItemAtPath:tmp error:nil];
		return reply_text(500, [NSString stringWithFormat:@"error: %@ has no usable Info.plist", appName]);
	}
	if (getuid() == 0) {
		chown_recursively(staged);
	}

	/*
	 * rename() cannot cross filesystems, and /var is its own volume on a real
	 * phone: then copy the staged bundle next to the target first.
	 */
	struct stat st_tmp, st_apps;
	NSString *nearby = nil;
	if (stat(tmp.fileSystemRepresentation, &st_tmp) == 0 &&
	    stat(APPS_DIR.fileSystemRepresentation, &st_apps) == 0 && st_tmp.st_dev != st_apps.st_dev) {
		nearby = [APPS_DIR stringByAppendingPathComponent:
		    [NSString stringWithFormat:@".topazd-%u-%u", getpid(), arc4random()]];
		NSError *cpErr = nil;
		if (![fm createDirectoryAtPath:nearby withIntermediateDirectories:NO attributes:nil error:&cpErr] ||
		    ![fm copyItemAtPath:staged toPath:[nearby stringByAppendingPathComponent:appName] error:&cpErr]) {
			[fm removeItemAtPath:nearby error:nil];
			[fm removeItemAtPath:tmp error:nil];
			return reply_text(500, [NSString stringWithFormat:@"error: copying into %@ failed: %@",
				       APPS_DIR, cpErr.localizedDescription]);
		}
		tlog(@"%@ and %@ are on different filesystems, staged a copy in %@", STAGING_DIR, APPS_DIR, nearby);
		staged = [nearby stringByAppendingPathComponent:appName];
	}

	/* Atomic swap when the app is already there, plain rename otherwise. */
	NSString *old = [[staged stringByDeletingLastPathComponent] stringByAppendingPathComponent:@"old.app"];
	if ([fm fileExistsAtPath:target]) {
		if (renamex_np(staged.fileSystemRepresentation, target.fileSystemRepresentation, RENAME_SWAP) != 0) {
			int e = errno;
			tlog(@"RENAME_SWAP failed (%s), falling back to move-aside", strerror(e));
			if (rename(target.fileSystemRepresentation, old.fileSystemRepresentation) != 0 ||
			    rename(staged.fileSystemRepresentation, target.fileSystemRepresentation) != 0) {
				NSString *m = [NSString stringWithFormat:@"error: replacing %@ failed: %s", target, strerror(errno)];
				[fm removeItemAtPath:tmp error:nil];
				if (nearby != nil) {
					[fm removeItemAtPath:nearby error:nil];
				}
				return reply_text(500, m);
			}
		} else {
			rename(staged.fileSystemRepresentation, old.fileSystemRepresentation);
		}
	} else if (rename(staged.fileSystemRepresentation, target.fileSystemRepresentation) != 0) {
		NSString *m = [NSString stringWithFormat:@"error: installing %@ failed: %s", target, strerror(errno)];
		[fm removeItemAtPath:tmp error:nil];
		if (nearby != nil) {
			[fm removeItemAtPath:nearby error:nil];
		}
		return reply_text(500, m);
	}

	[fm removeItemAtPath:tmp error:nil];
	if (nearby != nil) {
		[fm removeItemAtPath:nearby error:nil];
	}
	tlog(@"installed %@", target);

	NSString *bundleID = info[@"CFBundleIdentifier"];
#ifndef TOPAZD_HOSTTEST
	if (!register_bundle(target, &bundleID, &err)) {
		return reply_text(500, [NSString stringWithFormat:@"error: %@", err]);
	}
#endif
	if ([query[@"respring"] isEqualToString:@"1"]) {
		respring();
	}
	return reply_json(200, @{@"bundle": bundleID, @"path": target,
		       @"respring": @([query[@"respring"] isEqualToString:@"1"])});
}

static struct reply
ep_uninstall(NSDictionary *query)
{
	NSString *bundleID = query[@"bundle"];
	NSFileManager *fm = [NSFileManager defaultManager];

	if (bundleID.length == 0) {
		return reply_text(500, @"error: /uninstall needs ?bundle=ID");
	}
	LSApplicationProxy *app = proxy_for_bundle(bundleID);
	NSString *path = app.bundleURL.path;
	if (path == nil) {
		return reply_text(500, [NSString stringWithFormat:@"error: %@ is not installed", bundleID]);
	}
	if (![path.stringByStandardizingPath hasPrefix:[APPS_DIR stringByAppendingString:@"/"]]) {
		return reply_text(500, [NSString stringWithFormat:@"error: %@ is at %@, outside %@; not deleting it",
			       bundleID, path, APPS_DIR]);
	}
	BOOL unregistered = [workspace() unregisterApplication:[NSURL fileURLWithPath:path isDirectory:YES]];
	NSError *rmErr = nil;
	BOOL removed = [fm removeItemAtPath:path error:&rmErr];

	if (!removed) {
		return reply_text(500, [NSString stringWithFormat:@"error: unregister %@, delete %@ failed: %@",
			       unregistered ? @"ok" : @"failed", path, rmErr.localizedDescription]);
	}
	if ([query[@"respring"] isEqualToString:@"1"]) {
		respring();
	}
	return reply_json(200, @{@"bundle": bundleID, @"path": path, @"unregistered": @(unregistered), @"deleted": @YES});
}

static struct reply
ep_launch(NSDictionary *query)
{
	NSString *bundleID = query[@"bundle"];

	if (bundleID.length == 0) {
		return reply_text(500, @"error: /launch needs ?bundle=ID");
	}
	Class serviceCls = NSClassFromString(@"FBSSystemService");
	NSString *how = @"FBSSystemService openApplication:options:withResult:";
	__block NSError *fbErr = nil;
	BOOL launched = NO;

	if (serviceCls != nil) {
		FBSSystemService *svc = [serviceCls sharedService];
		dispatch_semaphore_t done = dispatch_semaphore_create(0);
		[svc openApplication:bundleID options:@{fbs_unlock_option_key(): @YES}
		    withResult:^(NSError *error) {
			fbErr = error;
			dispatch_semaphore_signal(done);
		}];
		if (dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, 15 * NSEC_PER_SEC)) != 0) {
			fbErr = [NSError errorWithDomain:@"topazd" code:-1
			    userInfo:@{NSLocalizedDescriptionKey: @"timed out after 15 s"}];
		}
		launched = (fbErr == nil);
	}
	if (!launched) {
		how = @"LSApplicationWorkspace openApplicationWithBundleID:";
		launched = [workspace() openApplicationWithBundleID:bundleID];
	}
	if (!launched) {
		return reply_text(500, [NSString stringWithFormat:@"error: launching %@ failed: %@",
			       bundleID, fbErr.localizedDescription ?: @"both FrontBoard and LaunchServices refused"]);
	}

	/* The pid shows up a moment after the open call returns. */
	LSApplicationProxy *app = proxy_for_bundle(bundleID);
	NSNumber *pid = nil;
	for (int i = 0; i < 20 && pid == nil; i++) {
		if (app.bundleURL.path != nil) {
			NSArray *pids = pids_under_path(app.bundleURL.path);
			pid = pids.firstObject;
		}
		if (pid == nil && serviceCls != nil &&
		    [[serviceCls sharedService] respondsToSelector:@selector(pidForApplication:)]) {
			int p = [[serviceCls sharedService] pidForApplication:bundleID];
			if (p > 0) {
				pid = @(p);
			}
		}
		if (pid == nil) {
			usleep(250 * 1000);
		}
	}
	return reply_json(200, @{@"bundle": bundleID, @"launched": @YES, @"via": how,
		       @"pid": pid ?: [NSNull null], @"path": app.bundleURL.path ?: [NSNull null]});
}

static struct reply
ep_terminate(NSDictionary *query)
{
	NSString *bundleID = query[@"bundle"];

	if (bundleID.length == 0) {
		return reply_text(500, @"error: /terminate needs ?bundle=ID");
	}
	LSApplicationProxy *app = proxy_for_bundle(bundleID);
	NSString *path = app.bundleURL.path;
	if (path == nil) {
		return reply_text(500, [NSString stringWithFormat:@"error: %@ is not installed", bundleID]);
	}
	NSArray<NSNumber *> *pids = pids_under_path(path);
	NSMutableArray *killed = [NSMutableArray array];
	NSMutableArray *failed = [NSMutableArray array];

	for (NSNumber *pid in pids) {
		if (kill(pid.intValue, SIGKILL) == 0) {
			[killed addObject:pid];
		} else {
			[failed addObject:@{@"pid": pid, @"error": @(strerror(errno))}];
		}
	}
	if (failed.count != 0) {
		return reply_json(500, @{@"bundle": bundleID, @"killed": killed, @"failed": failed});
	}
	return reply_json(200, @{@"bundle": bundleID, @"path": path, @"killed": killed});
}

static struct reply
ep_openurl(NSDictionary *query)
{
	NSString *urlString = query[@"url"];

	if (urlString.length == 0) {
		return reply_text(500, @"error: /openurl needs ?url=URL");
	}
	NSURL *url = [NSURL URLWithString:urlString];
	if (url == nil) {
		return reply_text(500, [NSString stringWithFormat:@"error: %@ is not a URL", urlString]);
	}
	LSApplicationWorkspace *ws = workspace();
	NSString *how = @"openSensitiveURL:withOptions:";
	BOOL ok = NO;

	if ([ws respondsToSelector:@selector(openSensitiveURL:withOptions:)]) {
		ok = [ws openSensitiveURL:url withOptions:@{fbs_unlock_option_key(): @YES}];
	}
	if (!ok) {
		how = @"openURL:";
		ok = [ws openURL:url];
	}
	if (!ok) {
		return reply_text(500, [NSString stringWithFormat:@"error: opening %@ failed", urlString]);
	}
	return reply_json(200, @{@"url": urlString, @"opened": @YES, @"via": how});
}

static struct reply
ep_apps(NSDictionary *query)
{
	BOOL all = [query[@"all"] isEqualToString:@"1"];
	LSApplicationWorkspace *ws = workspace();
	NSArray<LSApplicationProxy *> *apps = all && [ws respondsToSelector:@selector(allApplications)] ?
	    [ws allApplications] : [ws allInstalledApplications];
	NSMutableArray *out = [NSMutableArray array];

	for (LSApplicationProxy *app in apps) {
		NSString *name = nil;
		if ([app respondsToSelector:@selector(localizedNameForContext:)]) {
			id n = [app localizedNameForContext:nil];
			name = [n isKindOfClass:[NSString class]] ? n : nil;
		}
		[out addObject:@{
			 @"bundle": app.bundleIdentifier ?: app.applicationIdentifier ?: @"?",
			 @"path": app.bundleURL.path ?: [NSNull null],
			 @"type": app.applicationType ?: [NSNull null],
			 @"name": name ?: [NSNull null],
		 }];
	}
	[out sortUsingComparator:^NSComparisonResult (NSDictionary *a, NSDictionary *b) {
		return [a[@"bundle"] compare:b[@"bundle"]];
	}];
	return reply_json(200, out);
}

static struct reply
handle(NSString *method, NSString *path, NSDictionary *query, NSData *body)
{
	if ([path isEqualToString:@"/ping"]) {
		return reply_text(200, @"topazd ok");
	}
	if ([path isEqualToString:@"/install"]) {
		if (![method isEqualToString:@"POST"]) {
			return reply_text(500, @"error: /install needs POST with a tar body");
		}
		return ep_install(body, query);
	}
	if ([path isEqualToString:@"/uninstall"]) {
		return ep_uninstall(query);
	}
	if ([path isEqualToString:@"/launch"]) {
		return ep_launch(query);
	}
	if ([path isEqualToString:@"/terminate"]) {
		return ep_terminate(query);
	}
	if ([path isEqualToString:@"/openurl"]) {
		return ep_openurl(query);
	}
	if ([path isEqualToString:@"/apps"]) {
		return ep_apps(query);
	}
	if ([path isEqualToString:@"/respring"]) {
		respring();
		return reply_text(200, @"respringing");
	}
	return reply_text(500, [NSString stringWithFormat:@"error: no endpoint %@ (try /ping /install /uninstall /launch /terminate /openurl /apps /respring)", path]);
}

/* ---- socket plumbing ---- */

static BOOL
read_fully(int fd, void *buf, size_t want)
{
	uint8_t *p = buf;

	while (want != 0) {
		ssize_t n = read(fd, p, want);
		if (n <= 0) {
			return NO;
		}
		p += n;
		want -= (size_t)n;
	}
	return YES;
}

static void
write_fully(int fd, const void *buf, size_t len)
{
	const uint8_t *p = buf;

	while (len != 0) {
		ssize_t n = write(fd, p, len);
		if (n <= 0) {
			return;
		}
		p += n;
		len -= (size_t)n;
	}
}

static void
serve(int fd)
{
	NSMutableData *head = [NSMutableData data];
	NSRange blank = {NSNotFound, 0};

	/* Read up to the blank line that ends the headers. */
	while (head.length < 64 * 1024) {
		uint8_t byte;
		if (!read_fully(fd, &byte, 1)) {
			return;
		}
		[head appendBytes:&byte length:1];
		if (head.length >= 4) {
			const uint8_t *b = head.bytes;
			if (memcmp(b + head.length - 4, "\r\n\r\n", 4) == 0) {
				blank = NSMakeRange(head.length - 4, 4);
				break;
			}
			if (memcmp(b + head.length - 2, "\n\n", 2) == 0) {
				blank = NSMakeRange(head.length - 2, 2);
				break;
			}
		}
	}
	if (blank.location == NSNotFound) {
		tlog(@"request headers too large or connection closed");
		return;
	}
	NSString *headers = [[NSString alloc] initWithData:[head subdataWithRange:NSMakeRange(0, blank.location)]
	    encoding:NSUTF8StringEncoding];
	NSArray *lines = [headers componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]];
	NSArray *request = [lines.firstObject componentsSeparatedByString:@" "];

	if (request.count < 2) {
		struct reply r = reply_text(500, @"error: malformed request line");
		NSString *resp = [NSString stringWithFormat:
		    @"HTTP/1.1 500 Internal Server Error\r\nContent-Type: %@\r\nContent-Length: %lu\r\nConnection: close\r\n\r\n",
		    r.type, (unsigned long)r.body.length];
		write_fully(fd, resp.UTF8String, strlen(resp.UTF8String));
		write_fully(fd, r.body.bytes, r.body.length);
		return;
	}
	NSString *method = request[0];
	NSString *target = request[1];
	size_t content_length = 0;
	BOOL expect_continue = NO;

	for (NSString *line in lines) {
		NSString *lower = line.lowercaseString;
		if ([lower hasPrefix:@"content-length:"]) {
			content_length = (size_t)[[line substringFromIndex:15] longLongValue];
		} else if ([lower hasPrefix:@"expect:"] && [lower containsString:@"100-continue"]) {
			expect_continue = YES;
		}
	}
	if (expect_continue && content_length != 0) {
		static const char cont[] = "HTTP/1.1 100 Continue\r\n\r\n";
		write_fully(fd, cont, sizeof(cont) - 1);
	}

	NSString *path = target, *queryString = @"";
	NSRange q = [target rangeOfString:@"?"];
	if (q.location != NSNotFound) {
		path = [target substringToIndex:q.location];
		queryString = [target substringFromIndex:q.location + 1];
	}
	NSDictionary *query = parse_query(queryString);

	NSMutableData *body = [NSMutableData dataWithLength:content_length];
	if (content_length != 0 && !read_fully(fd, body.mutableBytes, content_length)) {
		tlog(@"%@ %@: body truncated (wanted %lu bytes)", method, target, (unsigned long)content_length);
		return;
	}
	tlog(@"%@ %@ (%lu byte body)", method, target, (unsigned long)content_length);

	struct reply r;
	@try {
		r = handle(method, percent_decode(path), query, body);
	} @catch (NSException *e) {
		r = reply_text(500, [NSString stringWithFormat:@"error: %@: %@", e.name, e.reason]);
	}
	tlog(@"%@ %@ -> %d (%lu bytes)", method, target, r.status, (unsigned long)r.body.length);

	NSString *resp = [NSString stringWithFormat:
	    @"HTTP/1.1 %d %s\r\nContent-Type: %@\r\nContent-Length: %lu\r\nConnection: close\r\n\r\n",
	    r.status, r.status == 200 ? "OK" : "Internal Server Error", r.type, (unsigned long)r.body.length];
	write_fully(fd, resp.UTF8String, strlen(resp.UTF8String));
	write_fully(fd, r.body.bytes, r.body.length);
}

static void
serve_forever(int listener)
{
	for (;;) {
		struct sockaddr_in peer;
		socklen_t plen = sizeof(peer);
		int fd = accept(listener, (struct sockaddr *)&peer, &plen);

		if (fd < 0) {
			if (errno != EINTR) {
				tlog(@"accept: %s", strerror(errno));
			}
			continue;
		}
		@autoreleasepool {
			tlog(@"connection from %s:%u", inet_ntoa(peer.sin_addr), ntohs(peer.sin_port));
			serve(fd);
		}
		close(fd);
	}
}

int
main(int argc, char *argv[])
{
	@autoreleasepool {
		uint16_t port = 7777;

		setvbuf(stdout, NULL, _IOLBF, 0);
		signal(SIGPIPE, SIG_IGN);
		for (int i = 1; i < argc; i++) {
			if (strncmp(argv[i], "--port=", 7) == 0) {
				port = (uint16_t)atoi(argv[i] + 7);
			}
		}
		load_private_frameworks();
		tlog(@"starting, uid %u, LSApplicationWorkspace %@, FBSSystemService %@", getuid(),
		    NSClassFromString(@"LSApplicationWorkspace") != nil ? @"ok" : @"MISSING",
		    NSClassFromString(@"FBSSystemService") != nil ? @"ok" : @"MISSING");

		int listener = socket(AF_INET, SOCK_STREAM, 0);
		int one = 1;
		if (listener < 0) {
			tlog(@"socket: %s", strerror(errno));
			return 1;
		}
		setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
		struct sockaddr_in addr = {
			.sin_len = sizeof(addr),
			.sin_family = AF_INET,
			.sin_port = htons(port),
			.sin_addr.s_addr = htonl(INADDR_ANY),
		};
		if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) != 0 || listen(listener, 16) != 0) {
			tlog(@"bind/listen on port %u: %s", port, strerror(errno));
			return 1;
		}
		tlog(@"listening on 0.0.0.0:%u", port);

		/*
		 * Requests are served one at a time on their own thread; the main
		 * thread runs the run loop so FrontBoard/LaunchServices callbacks can
		 * arrive while a request waits for them.
		 */
		[NSThread detachNewThreadWithBlock:^{
			serve_forever(listener);
		}];
		CFRunLoopRun();
		return 0;
	}
}
