const traceDllPath = 'C:/GumTrace/GumTrace.dll'
const targetDll = 'GameAssembly.dll'

let gumtrace_init = null
let gumtrace_run = null
let gumtrace_unrun = null
let gumtraceModule = null

function loadGumTrace() {
    if (gumtraceModule === null) {
        gumtraceModule = Module.load(traceDllPath)
    }

    gumtrace_init = new NativeFunction(gumtraceModule.getExportByName('init'), 'void', ['pointer', 'pointer', 'int', 'pointer'])
    gumtrace_run = new NativeFunction(gumtraceModule.getExportByName('run'), 'void', [])
    gumtrace_unrun = new NativeFunction(gumtraceModule.getExportByName('unrun'), 'void', [])
}

function startTrace() {
    loadGumTrace()

    const moduleNames = Memory.allocUtf8String(targetDll)
    const outputPath = Memory.allocUtf8String('C:/GumTrace/gumtrace.log')
    const threadId = 0
    const options = Memory.alloc(8)

    options.writeU64(0)

    console.log('start trace')

    gumtrace_init(moduleNames, outputPath, threadId, options)
    gumtrace_run()
}

function stopTrace() {
    console.log('stop trace')
    gumtrace_unrun()
}

let isTrace = false
function hook() {
    const kernel32 = Process.getModuleByName('kernel32.dll')
    const loadLibraryW = kernel32.getExportByName('LoadLibraryW')
    Interceptor.attach(loadLibraryW, {
        onEnter(args) {
            const path = args[0].readUtf16String()
            if (path && path.toLowerCase().indexOf(targetDll.toLowerCase()) !== -1) {
                this.shouldHook = true
            }
        },
        onLeave() {
            if (this.shouldHook) {
                const targetModule = Process.getModuleByName(targetDll)
                Interceptor.attach(targetModule.base.add(0x1A20E7), {
                    onEnter() {
                        if (!isTrace) {
                            isTrace = true
                            startTrace()
                            this.tracing = true
                        }
                    },
                    onLeave() {
                        if (this.tracing) {
                            stopTrace()
                        }
                    }
                })
            }
        }
    })
}

setImmediate(hook)
