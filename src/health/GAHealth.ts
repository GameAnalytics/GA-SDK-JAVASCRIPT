module gameanalytics
{
    export module health
    {
        export interface HealthSnapshot
        {
            memory_used_mb: number;
            hardware_concurrency: number;
            screen_width: number;
            screen_height: number;
            cpu_model: string;
            hardware: string;
            gpu_model: string;
            screen_resolution: string;
        }

        export class GAHealth
        {
            private static readonly FPS_MAX: number = 120;
            private static readonly MEM_INTERVAL: number = 5000;

            private static _enabled: boolean = false;
            private static rafId: number = 0;
            private static lastFrameTime: number = 0;
            private static fpsBuckets: number[] = [];
            private static frameAccum: number = 0;
            private static frameCount: number = 0;
            private static fpsTimer: number = 0;
            private static memTimer: number = 0;
            private static memSysBuckets: number[] = [];
            private static memAppBuckets: number[] = [];

            // Injected by GameAnalytics.init(), mirroring GAHealth(GAPlatform*) in C++.
            // The five values C++ reads in its constructor are cached once here;
            // getBootTime/getAppMemoryUsage/getSysMemoryUsage stay live calls.
            private static platform: gameanalytics.platform.GAPlatform = null;
            private static _cpuModel: string = "";
            private static _numCores: number = -1;
            private static _hardware: string = "";
            private static _gpuModel: string = "";
            private static _totalMemory: number = -1;
            private static _screenResolution: string | null = null;

            public static setPlatform(p: gameanalytics.platform.GAPlatform): void
            {
                GAHealth.platform = p;
                if (p)
                {
                    GAHealth._cpuModel    = p.getCpuModel();
                    GAHealth._numCores    = p.getNumCpuCores();
                    GAHealth._hardware    = p.getDeviceModel();
                    GAHealth._gpuModel    = p.getGpuModel();
                    GAHealth._totalMemory = p.getTotalDeviceMemory();
                }
            }

            private constructor() {}

            private static reset(): void
            {
                GAHealth.frameAccum = 0;
                GAHealth.frameCount = 0;
                GAHealth.fpsTimer = 0;
                GAHealth.memTimer = 0;
            }

            private static sampleMemory(): void
            {
                if (!GAHealth.platform) { return; }
                var total: number = GAHealth._totalMemory;
                var app: number = GAHealth.platform.getAppMemoryUsage();
                var sys: number = GAHealth.platform.getSysMemoryUsage();
                if (total > 0 && sys >= 0)
                {
                    GAHealth.memSysBuckets[Math.min(100, Math.max(0, Math.round(sys / total * 100)))]++;
                }
                if (total > 0 && app >= 0)
                {
                    GAHealth.memAppBuckets[Math.min(100, Math.max(0, Math.round(app / total * 100)))]++;
                }
            }

            private static getGpuModel(): string { return GAHealth._gpuModel; }
            private static getHardware(): string { return GAHealth._hardware; }
            private static getDeviceMemoryBytes(): number { return GAHealth._totalMemory; }

            private static getScreenResolution(): string
            {
                if (GAHealth._screenResolution !== null) { return GAHealth._screenResolution; }
                var w: number = (typeof screen !== 'undefined') ? screen.width : -1;
                var h: number = (typeof screen !== 'undefined') ? screen.height : -1;
                GAHealth._screenResolution = w + 'x' + h;
                return GAHealth._screenResolution;
            }

            public static configure(enabled: boolean): void
            {
                GAHealth._enabled = enabled;
                if (enabled)
                {
                    GAHealth.startTracking();
                }
                else
                {
                    GAHealth.stopTracking();
                }
            }

            private static startTracking(): void
            {
                if (typeof requestAnimationFrame === 'undefined')
                {
                    return;
                }

                GAHealth.reset();
                GAHealth.fpsBuckets = new Array(GAHealth.FPS_MAX + 1).fill(0);
                GAHealth.memSysBuckets = new Array(101).fill(0);
                GAHealth.memAppBuckets = new Array(101).fill(0);
                GAHealth.lastFrameTime = (typeof performance !== 'undefined') ? performance.now() : Date.now();

                var tick = function(now: number): void
                {
                    if (!GAHealth._enabled)
                    {
                        return;
                    }
                    var delta: number = now - GAHealth.lastFrameTime;
                    if (delta > 0)
                    {
                        GAHealth.frameAccum += 1000 / delta;
                        GAHealth.frameCount++;
                        GAHealth.fpsTimer += delta;
                        GAHealth.memTimer += delta;

                        if (GAHealth.fpsTimer >= 1000)
                        {
                            var avgFps: number = Math.min(GAHealth.FPS_MAX, Math.max(0, Math.round(GAHealth.frameAccum / GAHealth.frameCount)));
                            GAHealth.fpsBuckets[avgFps]++;
                            GAHealth.frameAccum = 0;
                            GAHealth.frameCount = 0;
                            GAHealth.fpsTimer -= 1000;
                        }

                        if (GAHealth.memTimer >= GAHealth.MEM_INTERVAL)
                        {
                            GAHealth.sampleMemory();
                            GAHealth.memTimer -= GAHealth.MEM_INTERVAL;
                        }
                    }
                    GAHealth.lastFrameTime = now;
                    GAHealth.rafId = requestAnimationFrame(tick);
                };

                GAHealth.rafId = requestAnimationFrame(tick);
            }

            private static stopTracking(): void
            {
                if (typeof cancelAnimationFrame !== 'undefined' && GAHealth.rafId)
                {
                    cancelAnimationFrame(GAHealth.rafId);
                    GAHealth.rafId = 0;
                }
            }

            public static getSnapshot(): HealthSnapshot
            {
                var appBytes: number = GAHealth.platform ? GAHealth.platform.getAppMemoryUsage() : -1;
                var memMb: number = appBytes >= 0 ? Math.round(appBytes / 1048576) : -1;

                return {
                    memory_used_mb: memMb,
                    hardware_concurrency: GAHealth._numCores,
                    screen_width: (typeof screen !== 'undefined') ? screen.width : -1,
                    screen_height: (typeof screen !== 'undefined') ? screen.height : -1,
                    cpu_model: GAHealth._cpuModel || 'unknown',
                    hardware: GAHealth.getHardware(),
                    gpu_model: GAHealth.getGpuModel(),
                    screen_resolution: GAHealth.getScreenResolution()
                };
            }

            public static addHealthAnnotations(out: {[key: string]: any}): void
            {
                out['cpu_model'] = GAHealth._cpuModel || 'unknown';

                out['hardware'] = GAHealth.getHardware() || 'unknown';

                var gpuModel: string = GAHealth.getGpuModel();
                if (gpuModel) { out['gpu_model'] = gpuModel; }

                var numCores: number = GAHealth._numCores;
                if (numCores > 0) { out['cpu_num_cores'] = numCores; }
            }

            public static addPerformanceData(out: {[key: string]: any}): void
            {
                out['fps_data_table'] = GAHealth.fpsBuckets.slice();

                if (GAHealth.getDeviceMemoryBytes() > 0)
                {
                    out['memory_sys_data_table'] = GAHealth.memSysBuckets.slice();
                    out['memory_app_data_table'] = GAHealth.memAppBuckets.slice();
                }
            }

            public static addSDKInitData(out: {[key: string]: any}): void
            {
                var bootTime: number = GAHealth.platform ? GAHealth.platform.getBootTime() : -1;
                if (bootTime > 0) { out['app_boot_time'] = bootTime; }
            }

            public static isEnabled(): boolean
            {
                return GAHealth._enabled;
            }
        }
    }
}
