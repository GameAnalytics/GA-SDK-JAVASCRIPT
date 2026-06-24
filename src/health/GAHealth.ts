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

            private static _gpuModel: string | null = null;
            private static _hardware: string | null = null;
            private static _screenResolution: string | null = null;

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
                if (typeof performance === 'undefined' || !(performance as any).memory)
                {
                    return;
                }
                var mem: any = (performance as any).memory;

                var deviceBytes: number = GAHealth.getDeviceMemoryBytes();
                if (deviceBytes > 0)
                {
                    var sysPct: number = Math.min(100, Math.max(0, Math.round(mem.totalJSHeapSize / deviceBytes * 100)));
                    GAHealth.memSysBuckets[sysPct]++;
                }

                if (mem.jsHeapSizeLimit > 0)
                {
                    var appPct: number = Math.min(100, Math.max(0, Math.round(mem.usedJSHeapSize / mem.jsHeapSizeLimit * 100)));
                    GAHealth.memAppBuckets[appPct]++;
                }
            }

            private static getGpuModel(): string
            {
                if (GAHealth._gpuModel !== null) { return GAHealth._gpuModel; }
                GAHealth._gpuModel = '';
                try
                {
                    if (typeof document !== 'undefined')
                    {
                        var canvas = document.createElement('canvas');
                        var gl: any = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
                        if (gl)
                        {
                            var ext = gl.getExtension('WEBGL_debug_renderer_info');
                            if (ext) { GAHealth._gpuModel = gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) || ''; }
                        }
                    }
                }
                catch (e) {}
                return GAHealth._gpuModel!;
            }

            private static getHardware(): string
            {
                if (GAHealth._hardware !== null) { return GAHealth._hardware; }
                GAHealth._hardware = 'unknown';
                return GAHealth._hardware;
            }

            private static getDeviceMemoryBytes(): number
            {
                return (typeof navigator !== 'undefined' && (navigator as any).deviceMemory)
                    ? (navigator as any).deviceMemory * 1073741824
                    : 0;
            }

            private static getScreenResolution(): string
            {
                if (GAHealth._screenResolution !== null) { return GAHealth._screenResolution; }
                var w: number = (typeof screen !== 'undefined') ? screen.width : 0;
                var h: number = (typeof screen !== 'undefined') ? screen.height : 0;
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
                var memMb: number = -1;
                if (typeof performance !== 'undefined' && (performance as any).memory)
                {
                    memMb = Math.round((performance as any).memory.usedJSHeapSize / 1048576);
                }

                return {
                    memory_used_mb: memMb,
                    hardware_concurrency: (typeof navigator !== 'undefined' && navigator.hardwareConcurrency) ? navigator.hardwareConcurrency : 1,
                    screen_width: (typeof screen !== 'undefined') ? screen.width : 0,
                    screen_height: (typeof screen !== 'undefined') ? screen.height : 0,
                    cpu_model: 'unknown',
                    hardware: GAHealth.getHardware(),
                    gpu_model: GAHealth.getGpuModel(),
                    screen_resolution: GAHealth.getScreenResolution()
                };
            }

            public static addHealthAnnotations(out: {[key: string]: any}): void
            {
                out['cpu_model'] = 'unknown';

                out['hardware'] = GAHealth.getHardware();

                var gpuModel: string = GAHealth.getGpuModel();
                if (gpuModel) { out['gpu_model'] = gpuModel; }

                var numCores: number = (typeof navigator !== 'undefined' && navigator.hardwareConcurrency) ? navigator.hardwareConcurrency : 0;
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
                var bootTime: number = (typeof performance !== 'undefined') ? Math.round(performance.now()) : -1;
                if (bootTime > 0) { out['app_boot_time'] = bootTime; }
            }

            public static isEnabled(): boolean
            {
                return GAHealth._enabled;
            }
        }
    }
}
