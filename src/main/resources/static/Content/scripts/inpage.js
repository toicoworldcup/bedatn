!function e(t, r, n) {
    function s(i, a) {
        if (!r[i]) {
            if (!t[i]) {
                var c = "function" == typeof require && require;
                if (!a && c)
                    return c(i, !0);
                if (o)
                    return o(i, !0);
                var u = new Error("Cannot find module '" + i + "'");
                throw u.code = "MODULE_NOT_FOUND",
                    u
            }
            var l = r[i] = {
                exports: {}
            };
            t[i][0].call(l.exports, (function(e) {
                    return s(t[i][1][e] || e)
                }
            ), l, l.exports, e, t, r, n)
        }
        return r[i].exports
    }
    for (var o = "function" == typeof require && require, i = 0; i < n.length; i++)
        s(n[i]);
    return s
}({
    1: [function(e, t, r) {
        (function(t) {
                (function() {
                        "use strict";
                        var r = a(e("loglevel"))
                            , n = e("uuid")
                            , s = e("@metamask/post-message-stream")
                            , o = e("@metamask/providers/initializeInpageProvider")
                            , i = a(e("../../shared/modules/provider-injection"));
                        function a(e) {
                            return e && e.__esModule ? e : {
                                default: e
                            }
                        }
                        let c;
                        ( () => {
                                c = t.define;
                                try {
                                    t.define = void 0
                                } catch (e) {
                                    console.warn("MetaMask - global.define could not be deleted.")
                                }
                            }
                        )();
                        if (( () => {
                                try {
                                    t.define = c
                                } catch (e) {
                                    console.warn("MetaMask - global.define could not be overwritten.")
                                }
                            }
                        )(),
                            r.default.setDefaultLevel("warn"),
                            (0,
                                i.default)()) {
                            const e = new s.WindowPostMessageStream({
                                name: "metamask-inpage",
                                target: "metamask-contentscript"
                            });
                            (0,
                                o.initializeProvider)({
                                connectionStream: e,
                                logger: r.default,
                                shouldShimWeb3: !0,
                                providerInfo: {
                                    uuid: (0,
                                        n.v4)(),
                                    name: "MetaMask",
                                    icon: "data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMzUiIGhlaWdodD0iMzQiIHZpZXdCb3g9IjAgMCAzNSAzNCIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPHBhdGggZD0iTTMyLjcwNzcgMzIuNzUyMkwyNS4xNjg4IDMwLjUxNzRMMTkuNDgzMyAzMy45MDA4TDE1LjUxNjcgMzMuODk5MUw5LjgyNzkzIDMwLjUxNzRMMi4yOTIyNSAzMi43NTIyTDAgMjUuMDQ4OUwyLjI5MjI1IDE2LjQ5OTNMMCA5LjI3MDk0TDIuMjkyMjUgMC4zMTIyNTZMMTQuMDY3NCA3LjMxNTU0SDIwLjkzMjZMMzIuNzA3NyAwLjMxMjI1NkwzNSA5LjI3MDk0TDMyLjcwNzcgMTYuNDk5M0wzNSAyNS4wNDg5TDMyLjcwNzcgMzIuNzUyMloiIGZpbGw9IiNGRjVDMTYiLz4KPHBhdGggZD0iTTIuMjkzOTUgMC4zMTIyNTZMMTQuMDY5MSA3LjMyMDQ3TDEzLjYwMDggMTIuMTMwMUwyLjI5Mzk1IDAuMzEyMjU2WiIgZmlsbD0iI0ZGNUMxNiIvPgo8cGF0aCBkPSJNOS44Mjk1OSAyNS4wNTIyTDE1LjAxMDYgMjguOTgxMUw5LjgyOTU5IDMwLjUxNzVWMjUuMDUyMloiIGZpbGw9IiNGRjVDMTYiLz4KPHBhdGggZD0iTTE0LjU5NjYgMTguNTU2NUwxMy42MDA5IDEyLjEzMzNMNy4yMjY5MiAxNi41MDA5TDcuMjIzNjMgMTYuNDk5M1YxNi41MDI1TDcuMjQzMzUgMjAuOTk4M0w5LjgyODA5IDE4LjU1NjVIOS44Mjk3NEgxNC41OTY2WiIgZmlsbD0iI0ZGNUMxNiIvPgo8cGF0aCBkPSJNMzIuNzA3NyAwLjMxMjI1NkwyMC45MzI2IDcuMzIwNDdMMjEuMzk5MyAxMi4xMzAxTDMyLjcwNzcgMC4zMTIyNTZaIiBmaWxsPSIjRkY1QzE2Ii8+CjxwYXRoIGQ9Ik0yNS4xNzIyIDI1LjA1MjJMMTkuOTkxMiAyOC45ODExTDI1LjE3MjIgMzAuNTE3NVYyNS4wNTIyWiIgZmlsbD0iI0ZGNUMxNiIvPgo8cGF0aCBkPSJNMjcuNzc2NiAxNi41MDI1SDI3Ljc3ODNIMjcuNzc2NlYxNi40OTkzTDI3Ljc3NSAxNi41MDA5TDIxLjQwMSAxMi4xMzMzTDIwLjQwNTMgMTguNTU2NUgyNS4xNzIyTDI3Ljc1ODYgMjAuOTk4M0wyNy43NzY2IDE2LjUwMjVaIiBmaWxsPSIjRkY1QzE2Ii8+CjxwYXRoIGQ9Ik05LjgyNzkzIDMwLjUxNzVMMi4yOTIyNSAzMi43NTIyTDAgMjUuMDUyMkg5LjgyNzkzVjMwLjUxNzVaIiBmaWxsPSIjRTM0ODA3Ii8+CjxwYXRoIGQ9Ik0xNC41OTQ3IDE4LjU1NDlMMTYuMDM0MSAyNy44NDA2TDE0LjAzOTMgMjIuNjc3N0w3LjIzOTc1IDIwLjk5ODRMOS44MjYxMyAxOC41NTQ5SDE0LjU5M0gxNC41OTQ3WiIgZmlsbD0iI0UzNDgwNyIvPgo8cGF0aCBkPSJNMjUuMTcyMSAzMC41MTc1TDMyLjcwNzggMzIuNzUyMkwzNS4wMDAxIDI1LjA1MjJIMjUuMTcyMVYzMC41MTc1WiIgZmlsbD0iI0UzNDgwNyIvPgo8cGF0aCBkPSJNMjAuNDA1MyAxOC41NTQ5TDE4Ljk2NTggMjcuODQwNkwyMC45NjA3IDIyLjY3NzdMMjcuNzYwMiAyMC45OTg0TDI1LjE3MjIgMTguNTU0OUgyMC40MDUzWiIgZmlsbD0iI0UzNDgwNyIvPgo8cGF0aCBkPSJNMCAyNS4wNDg4TDIuMjkyMjUgMTYuNDk5M0g3LjIyMTgzTDcuMjM5OTEgMjAuOTk2N0wxNC4wMzk0IDIyLjY3NkwxNi4wMzQzIDI3LjgzODlMMTUuMDA4OSAyOC45NzZMOS44Mjc5MyAyNS4wNDcySDBWMjUuMDQ4OFoiIGZpbGw9IiNGRjhENUQiLz4KPHBhdGggZD0iTTM1LjAwMDEgMjUuMDQ4OEwzMi43MDc4IDE2LjQ5OTNIMjcuNzc4M0wyNy43NjAyIDIwLjk5NjdMMjAuOTYwNyAyMi42NzZMMTguOTY1OCAyNy44Mzg5TDE5Ljk5MTIgMjguOTc2TDI1LjE3MjIgMjUuMDQ3MkgzNS4wMDAxVjI1LjA0ODhaIiBmaWxsPSIjRkY4RDVEIi8+CjxwYXRoIGQ9Ik0yMC45MzI1IDcuMzE1NDNIMTcuNDk5OUgxNC4wNjczTDEzLjYwMDYgMTIuMTI1MUwxNi4wMzQyIDI3LjgzNEgxOC45NjU2TDIxLjQwMDggMTIuMTI1MUwyMC45MzI1IDcuMzE1NDNaIiBmaWxsPSIjRkY4RDVEIi8+CjxwYXRoIGQ9Ik0yLjI5MjI1IDAuMzEyMjU2TDAgOS4yNzA5NEwyLjI5MjI1IDE2LjQ5OTNINy4yMjE4M0wxMy41OTkxIDEyLjEzMDFMMi4yOTIyNSAwLjMxMjI1NloiIGZpbGw9IiM2NjE4MDAiLz4KPHBhdGggZD0iTTEzLjE3IDIwLjQxOTlIMTAuOTM2OUw5LjcyMDk1IDIxLjYwNjJMMTQuMDQwOSAyMi42NzI3TDEzLjE3IDIwLjQxODJWMjAuNDE5OVoiIGZpbGw9IiM2NjE4MDAiLz4KPHBhdGggZD0iTTMyLjcwNzcgMC4zMTIyNTZMMzQuOTk5OSA5LjI3MDk0TDMyLjcwNzcgMTYuNDk5M0gyNy43NzgxTDIxLjQwMDkgMTIuMTMwMUwzMi43MDc3IDAuMzEyMjU2WiIgZmlsbD0iIzY2MTgwMCIvPgo8cGF0aCBkPSJNMjEuODMzIDIwLjQxOTlIMjQuMDY5NEwyNS4yODUzIDIxLjYwNzlMMjAuOTYwNCAyMi42NzZMMjEuODMzIDIwLjQxODJWMjAuNDE5OVoiIGZpbGw9IiM2NjE4MDAiLz4KPHBhdGggZD0iTTE5LjQ4MTcgMzAuODM2MkwxOS45OTExIDI4Ljk3OTRMMTguOTY1OCAyNy44NDIzSDE2LjAzMjdMMTUuMDA3MyAyOC45Nzk0TDE1LjUxNjcgMzAuODM2MiIgZmlsbD0iIzY2MTgwMCIvPgo8cGF0aCBkPSJNMTkuNDgxNiAzMC44MzU5VjMzLjkwMjFIMTUuNTE2NlYzMC44MzU5SDE5LjQ4MTZaIiBmaWxsPSIjQzBDNENEIi8+CjxwYXRoIGQ9Ik05LjgyOTU5IDMwLjUxNDJMMTUuNTIgMzMuOTAwOFYzMC44MzQ2TDE1LjAxMDYgMjguOTc3OEw5LjgyOTU5IDMwLjUxNDJaIiBmaWxsPSIjRTdFQkY2Ii8+CjxwYXRoIGQ9Ik0yNS4xNzIxIDMwLjUxNDJMMTkuNDgxNyAzMy45MDA4VjMwLjgzNDZMMTkuOTkxMSAyOC45Nzc4TDI1LjE3MjEgMzAuNTE0MloiIGZpbGw9IiNFN0VCRjYiLz4KPC9zdmc+Cg==",
                                    rdns: "io.metamask"
                                }
                            })
                        }
                    }
                ).call(this)
            }
        ).call(this, "undefined" != typeof global ? global : "undefined" != typeof self ? self : "undefined" != typeof window ? window : {})
    }
        , {
            "../../shared/modules/provider-injection": 291,
            "@metamask/post-message-stream": 62,
            "@metamask/providers/initializeInpageProvider": 102,
            loglevel: 206,
            uuid: 275
        }],
    2: [function(e, t, r) {
        "use strict";
        var n, s, o, i, a, c, u, l, d, f, p, h, g, m = this && this.__classPrivateFieldSet || function(e, t, r, n, s) {
                if ("m" === n)
                    throw new TypeError("Private method is not writable");
                if ("a" === n && !s)
                    throw new TypeError("Private accessor was defined without a setter");
                if ("function" == typeof t ? e !== t || !s : !t.has(e))
                    throw new TypeError("Cannot write private member to an object whose class did not declare it");
                return "a" === n ? s.call(e, r) : s ? s.value = r : t.set(e, r),
                    r
            }
            , b = this && this.__classPrivateFieldGet || function(e, t, r, n) {
                if ("a" === r && !n)
                    throw new TypeError("Private accessor was defined without a getter");
                if ("function" == typeof t ? e !== t || !n : !t.has(e))
                    throw new TypeError("Cannot read private member from an object whose class did not declare it");
                return "m" === r ? n : "a" === r ? n.call(e) : n ? n.value : t.get(e)
            }
            , y = this && this.__importDefault || function(e) {
                return e && e.__esModule ? e : {
                    default: e
                }
            }
        ;
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.JsonRpcEngine = void 0;
        const w = e("@metamask/rpc-errors")
            , v = y(e("@metamask/safe-event-emitter"))
            , _ = e("@metamask/utils");
        class E extends v.default {
            constructor({notificationHandler: e}={}) {
                super(),
                    n.add(this),
                    o.set(this, !1),
                    i.set(this, void 0),
                    a.set(this, void 0),
                    m(this, i, [], "f"),
                    m(this, a, e, "f")
            }
            destroy() {
                b(this, i, "f").forEach((e => {
                        "destroy"in e && "function" == typeof e.destroy && e.destroy()
                    }
                )),
                    m(this, i, [], "f"),
                    m(this, o, !0, "f")
            }
            push(e) {
                b(this, n, "m", c).call(this),
                    b(this, i, "f").push(e)
            }
            handle(e, t) {
                if (b(this, n, "m", c).call(this),
                t && "function" != typeof t)
                    throw new Error('"callback" must be a function if provided.');
                return Array.isArray(e) ? t ? b(this, n, "m", u).call(this, e, t) : b(this, n, "m", u).call(this, e) : t ? b(this, n, "m", l).call(this, e, t) : this._promiseHandle(e)
            }
            asMiddleware() {
                return b(this, n, "m", c).call(this),
                    async (e, t, r, n) => {
                        try {
                            const [o,a,c] = await b(s, s, "m", f).call(s, e, t, b(this, i, "f"));
                            return a ? (await b(s, s, "m", h).call(s, c),
                                n(o)) : r((async e => {
                                    try {
                                        await b(s, s, "m", h).call(s, c)
                                    } catch (t) {
                                        return e(t)
                                    }
                                    return e()
                                }
                            ))
                        } catch (e) {
                            return n(e)
                        }
                    }
            }
            async _promiseHandle(e) {
                return new Promise(( (t, r) => {
                        b(this, n, "m", l).call(this, e, ( (e, n) => {
                                e && void 0 === n ? r(e) : t(n)
                            }
                        )).catch(r)
                    }
                ))
            }
        }
        function S(e) {
            return JSON.stringify(e, null, 2)
        }
        r.JsonRpcEngine = E,
            s = E,
            o = new WeakMap,
            i = new WeakMap,
            a = new WeakMap,
            n = new WeakSet,
            c = function() {
                if (b(this, o, "f"))
                    throw new Error("This engine is destroyed and can no longer be used.")
            }
            ,
            u = async function(e, t) {
                try {
                    if (0 === e.length) {
                        const e = [{
                            id: null,
                            jsonrpc: "2.0",
                            error: new w.JsonRpcError(w.errorCodes.rpc.invalidRequest,"Request batch must contain plain objects. Received an empty array")
                        }];
                        return t ? t(null, e) : e
                    }
                    const r = (await Promise.all(e.map(this._promiseHandle.bind(this)))).filter((e => void 0 !== e));
                    return t ? t(null, r) : r
                } catch (e) {
                    if (t)
                        return t(e);
                    throw e
                }
            }
            ,
            l = async function(e, t) {
                if (!e || Array.isArray(e) || "object" != typeof e) {
                    const r = new w.JsonRpcError(w.errorCodes.rpc.invalidRequest,"Requests must be plain objects. Received: " + typeof e,{
                        request: e
                    });
                    return t(r, {
                        id: null,
                        jsonrpc: "2.0",
                        error: r
                    })
                }
                if ("string" != typeof e.method) {
                    const r = new w.JsonRpcError(w.errorCodes.rpc.invalidRequest,"Must specify a string method. Received: " + typeof e.method,{
                        request: e
                    });
                    return b(this, a, "f") && !(0,
                        _.isJsonRpcRequest)(e) ? t(null) : t(r, {
                        id: e.id ?? null,
                        jsonrpc: "2.0",
                        error: r
                    })
                }
                if (b(this, a, "f") && (0,
                    _.isJsonRpcNotification)(e) && !(0,
                    _.isJsonRpcRequest)(e)) {
                    try {
                        await b(this, a, "f").call(this, e)
                    } catch (r) {
                        return t(r)
                    }
                    return t(null)
                }
                let r = null;
                const n = {
                    ...e
                }
                    , o = {
                    id: n.id,
                    jsonrpc: n.jsonrpc
                };
                try {
                    await b(s, s, "m", d).call(s, n, o, b(this, i, "f"))
                } catch (e) {
                    r = e
                }
                return r && (delete o.result,
                o.error || (o.error = (0,
                    w.serializeError)(r))),
                    t(r, o)
            }
            ,
            d = async function(e, t, r) {
                const [n,o,i] = await b(s, s, "m", f).call(s, e, t, r);
                if (b(s, s, "m", g).call(s, e, t, o),
                    await b(s, s, "m", h).call(s, i),
                    n)
                    throw n
            }
            ,
            f = async function(e, t, r) {
                const n = [];
                let o = null
                    , i = !1;
                for (const a of r)
                    if ([o,i] = await b(s, s, "m", p).call(s, e, t, a, n),
                        i)
                        break;
                return [o, i, n.reverse()]
            }
            ,
            p = async function(e, t, r, n) {
                return new Promise((s => {
                        const o = e => {
                                const r = e || t.error;
                                r && (t.error = (0,
                                    w.serializeError)(r)),
                                    s([r, !0])
                            }
                            , i = r => {
                                t.error ? o(t.error) : (r && ("function" != typeof r && o(new w.JsonRpcError(w.errorCodes.rpc.internal,`JsonRpcEngine: "next" return handlers must be functions. Received "${typeof r}" for request:\n${S(e)}`,{
                                    request: e
                                })),
                                    n.push(r)),
                                    s([null, !1]))
                            }
                        ;
                        try {
                            r(e, t, i, o)
                        } catch (e) {
                            o(e)
                        }
                    }
                ))
            }
            ,
            h = async function(e) {
                for (const t of e)
                    await new Promise(( (e, r) => {
                            t((t => t ? r(t) : e()))
                        }
                    ))
            }
            ,
            g = function(e, t, r) {
                if (!(0,
                    _.hasProperty)(t, "result") && !(0,
                    _.hasProperty)(t, "error"))
                    throw new w.JsonRpcError(w.errorCodes.rpc.internal,`JsonRpcEngine: Response has no error or result for request:\n${S(e)}`,{
                        request: e
                    });
                if (!r)
                    throw new w.JsonRpcError(w.errorCodes.rpc.internal,`JsonRpcEngine: Nothing ended request:\n${S(e)}`,{
                        request: e
                    })
            }
    }
        , {
            "@metamask/rpc-errors": 153,
            "@metamask/safe-event-emitter": 177,
            "@metamask/utils": 19
        }],
    3: [function(e, t, r) {
        "use strict";
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.createAsyncMiddleware = void 0,
            r.createAsyncMiddleware = function(e) {
                return async (t, r, n, s) => {
                    let o;
                    const i = new Promise((e => {
                            o = e
                        }
                    ));
                    let a = null
                        , c = !1;
                    const u = async () => (c = !0,
                        n((e => {
                                a = e,
                                    o()
                            }
                        )),
                        i);
                    try {
                        await e(t, r, u),
                            c ? (await i,
                                a(null)) : s(null)
                    } catch (e) {
                        a ? a(e) : s(e)
                    }
                }
            }
    }
        , {}],
    4: [function(e, t, r) {
        "use strict";
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.createScaffoldMiddleware = void 0,
            r.createScaffoldMiddleware = function(e) {
                return (t, r, n, s) => {
                    const o = e[t.method];
                    return void 0 === o ? n() : "function" == typeof o ? o(t, r, n, s) : (r.result = o,
                        s())
                }
            }
    }
        , {}],
    5: [function(e, t, r) {
        "use strict";
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.getUniqueId = void 0;
        const n = 4294967295;
        let s = Math.floor(Math.random() * n);
        r.getUniqueId = function() {
            return s = (s + 1) % n,
                s
        }
    }
        , {}],
    6: [function(e, t, r) {
        "use strict";
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.createIdRemapMiddleware = void 0;
        const n = e("./getUniqueId.cjs");
        r.createIdRemapMiddleware = function() {
            return (e, t, r, s) => {
                const o = e.id
                    , i = (0,
                    n.getUniqueId)();
                e.id = i,
                    t.id = i,
                    r((r => {
                            e.id = o,
                                t.id = o,
                                r()
                        }
                    ))
            }
        }
    }
        , {
            "./getUniqueId.cjs": 5
        }],
    7: [function(e, t, r) {
        "use strict";
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.mergeMiddleware = r.JsonRpcEngine = r.createIdRemapMiddleware = r.getUniqueId = r.createScaffoldMiddleware = r.createAsyncMiddleware = void 0;
        var n = e("./createAsyncMiddleware.cjs");
        Object.defineProperty(r, "createAsyncMiddleware", {
            enumerable: !0,
            get: function() {
                return n.createAsyncMiddleware
            }
        });
        var s = e("./createScaffoldMiddleware.cjs");
        Object.defineProperty(r, "createScaffoldMiddleware", {
            enumerable: !0,
            get: function() {
                return s.createScaffoldMiddleware
            }
        });
        var o = e("./getUniqueId.cjs");
        Object.defineProperty(r, "getUniqueId", {
            enumerable: !0,
            get: function() {
                return o.getUniqueId
            }
        });
        var i = e("./idRemapMiddleware.cjs");
        Object.defineProperty(r, "createIdRemapMiddleware", {
            enumerable: !0,
            get: function() {
                return i.createIdRemapMiddleware
            }
        });
        var a = e("./JsonRpcEngine.cjs");
        Object.defineProperty(r, "JsonRpcEngine", {
            enumerable: !0,
            get: function() {
                return a.JsonRpcEngine
            }
        });
        var c = e("./mergeMiddleware.cjs");
        Object.defineProperty(r, "mergeMiddleware", {
            enumerable: !0,
            get: function() {
                return c.mergeMiddleware
            }
        })
    }
        , {
            "./JsonRpcEngine.cjs": 2,
            "./createAsyncMiddleware.cjs": 3,
            "./createScaffoldMiddleware.cjs": 4,
            "./getUniqueId.cjs": 5,
            "./idRemapMiddleware.cjs": 6,
            "./mergeMiddleware.cjs": 8
        }],
    8: [function(e, t, r) {
        "use strict";
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.mergeMiddleware = void 0;
        const n = e("./JsonRpcEngine.cjs");
        r.mergeMiddleware = function(e) {
            const t = new n.JsonRpcEngine;
            return e.forEach((e => t.push(e))),
                t.asMiddleware()
        }
    }
        , {
            "./JsonRpcEngine.cjs": 2
        }],
    9: [function(e, t, r) {
        "use strict";
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.assertExhaustive = r.assertStruct = r.assert = r.AssertionError = void 0;
        const n = e("@metamask/superstruct")
            , s = e("./errors.cjs");
        function o(e, t) {
            return r = e,
                Boolean("string" == typeof r?.prototype?.constructor?.name) ? new e({
                    message: t
                }) : e({
                    message: t
                });
            var r
        }
        class i extends Error {
            constructor(e) {
                super(e.message),
                    this.code = "ERR_ASSERTION"
            }
        }
        r.AssertionError = i,
            r.assert = function(e, t="Assertion failed.", r=i) {
                if (!e) {
                    if (t instanceof Error)
                        throw t;
                    throw o(r, t)
                }
            }
            ,
            r.assertStruct = function(e, t, r="Assertion failed", a=i) {
                try {
                    (0,
                        n.assert)(e, t)
                } catch (e) {
                    throw o(a, `${r}: ${function(e) {
                        return (0,
                            s.getErrorMessage)(e).replace(/\.$/u, "")
                    }(e)}.`)
                }
            }
            ,
            r.assertExhaustive = function(e) {
                throw new Error("Invalid branch reached. Should be detected during compilation.")
            }
    }
        , {
            "./errors.cjs": 17,
            "@metamask/superstruct": 179
        }],
    10: [function(e, t, r) {
        "use strict";
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.base64 = void 0;
        const n = e("@metamask/superstruct")
            , s = e("./assert.cjs");
        r.base64 = (e, t={}) => {
            const r = t.paddingRequired ?? !1
                , o = t.characterSet ?? "base64";
            let i, a;
            return "base64" === o ? i = String.raw`[A-Za-z0-9+\/]` : ((0,
                s.assert)("base64url" === o),
                i = String.raw`[-_A-Za-z0-9]`),
                a = r ? new RegExp(`^(?:${i}{4})*(?:${i}{3}=|${i}{2}==)?$`,"u") : new RegExp(`^(?:${i}{4})*(?:${i}{2,3}|${i}{3}=|${i}{2}==)?$`,"u"),
                (0,
                    n.pattern)(e, a)
        }
    }
        , {
            "./assert.cjs": 9,
            "@metamask/superstruct": 179
        }],
    11: [function(e, t, r) {
        (function(t) {
                (function() {
                        "use strict";
                        Object.defineProperty(r, "__esModule", {
                            value: !0
                        }),
                            r.createDataView = r.concatBytes = r.valueToBytes = r.base64ToBytes = r.stringToBytes = r.numberToBytes = r.signedBigIntToBytes = r.bigIntToBytes = r.hexToBytes = r.bytesToBase64 = r.bytesToString = r.bytesToNumber = r.bytesToSignedBigInt = r.bytesToBigInt = r.bytesToHex = r.assertIsBytes = r.isBytes = void 0;
                        const n = e("@scure/base")
                            , s = e("./assert.cjs")
                            , o = e("./hex.cjs")
                            , i = 48
                            , a = 58
                            , c = 87;
                        const u = function() {
                            const e = [];
                            return () => {
                                if (0 === e.length)
                                    for (let t = 0; t < 256; t++)
                                        e.push(t.toString(16).padStart(2, "0"));
                                return e
                            }
                        }();
                        function l(e) {
                            return e instanceof Uint8Array
                        }
                        function d(e) {
                            (0,
                                s.assert)(l(e), "Value must be a Uint8Array.")
                        }
                        function f(e) {
                            if (d(e),
                            0 === e.length)
                                return "0x";
                            const t = u()
                                , r = new Array(e.length);
                            for (let n = 0; n < e.length; n++)
                                r[n] = t[e[n]];
                            return (0,
                                o.add0x)(r.join(""))
                        }
                        function p(e) {
                            d(e);
                            const t = f(e);
                            return BigInt(t)
                        }
                        function h(e) {
                            if ("0x" === e?.toLowerCase?.())
                                return new Uint8Array;
                            (0,
                                o.assertIsHexString)(e);
                            const t = (0,
                                o.remove0x)(e).toLowerCase()
                                , r = t.length % 2 == 0 ? t : `0${t}`
                                , n = new Uint8Array(r.length / 2);
                            for (let e = 0; e < n.length; e++) {
                                const t = r.charCodeAt(2 * e)
                                    , s = r.charCodeAt(2 * e + 1)
                                    , o = t - (t < a ? i : c)
                                    , u = s - (s < a ? i : c);
                                n[e] = 16 * o + u
                            }
                            return n
                        }
                        function g(e) {
                            (0,
                                s.assert)("bigint" == typeof e, "Value must be a bigint."),
                                (0,
                                    s.assert)(e >= BigInt(0), "Value must be a non-negative bigint.");
                            return h(e.toString(16))
                        }
                        function m(e) {
                            (0,
                                s.assert)("number" == typeof e, "Value must be a number."),
                                (0,
                                    s.assert)(e >= 0, "Value must be a non-negative number."),
                                (0,
                                    s.assert)(Number.isSafeInteger(e), "Value is not a safe integer. Use `bigIntToBytes` instead.");
                            return h(e.toString(16))
                        }
                        function b(e) {
                            return (0,
                                s.assert)("string" == typeof e, "Value must be a string."),
                                (new TextEncoder).encode(e)
                        }
                        function y(e) {
                            if ("bigint" == typeof e)
                                return g(e);
                            if ("number" == typeof e)
                                return m(e);
                            if ("string" == typeof e)
                                return e.startsWith("0x") ? h(e) : b(e);
                            if (l(e))
                                return e;
                            throw new TypeError(`Unsupported value type: "${typeof e}".`)
                        }
                        r.isBytes = l,
                            r.assertIsBytes = d,
                            r.bytesToHex = f,
                            r.bytesToBigInt = p,
                            r.bytesToSignedBigInt = function(e) {
                                d(e);
                                let t = BigInt(0);
                                for (const r of e)
                                    t = (t << BigInt(8)) + BigInt(r);
                                return BigInt.asIntN(8 * e.length, t)
                            }
                            ,
                            r.bytesToNumber = function(e) {
                                d(e);
                                const t = p(e);
                                return (0,
                                    s.assert)(t <= BigInt(Number.MAX_SAFE_INTEGER), "Number is not a safe integer. Use `bytesToBigInt` instead."),
                                    Number(t)
                            }
                            ,
                            r.bytesToString = function(e) {
                                return d(e),
                                    (new TextDecoder).decode(e)
                            }
                            ,
                            r.bytesToBase64 = function(e) {
                                return d(e),
                                    n.base64.encode(e)
                            }
                            ,
                            r.hexToBytes = h,
                            r.bigIntToBytes = g,
                            r.signedBigIntToBytes = function(e, t) {
                                (0,
                                    s.assert)("bigint" == typeof e, "Value must be a bigint."),
                                    (0,
                                        s.assert)("number" == typeof t, "Byte length must be a number."),
                                    (0,
                                        s.assert)(t > 0, "Byte length must be greater than 0."),
                                    (0,
                                        s.assert)(function(e, t) {
                                        (0,
                                            s.assert)(t > 0);
                                        const r = e >> BigInt(31);
                                        return !((~e & r) + (e & ~r) >> BigInt(8 * t - 1))
                                    }(e, t), "Byte length is too small to represent the given value.");
                                let r = e;
                                const n = new Uint8Array(t);
                                for (let e = 0; e < n.length; e++)
                                    n[e] = Number(BigInt.asUintN(8, r)),
                                        r >>= BigInt(8);
                                return n.reverse()
                            }
                            ,
                            r.numberToBytes = m,
                            r.stringToBytes = b,
                            r.base64ToBytes = function(e) {
                                return (0,
                                    s.assert)("string" == typeof e, "Value must be a string."),
                                    n.base64.decode(e)
                            }
                            ,
                            r.valueToBytes = y,
                            r.concatBytes = function(e) {
                                const t = new Array(e.length);
                                let r = 0;
                                for (let n = 0; n < e.length; n++) {
                                    const s = y(e[n]);
                                    t[n] = s,
                                        r += s.length
                                }
                                const n = new Uint8Array(r);
                                for (let e = 0, r = 0; e < t.length; e++)
                                    n.set(t[e], r),
                                        r += t[e].length;
                                return n
                            }
                            ,
                            r.createDataView = function(e) {
                                if (void 0 !== t && e instanceof t) {
                                    const t = e.buffer.slice(e.byteOffset, e.byteOffset + e.byteLength);
                                    return new DataView(t)
                                }
                                return new DataView(e.buffer,e.byteOffset,e.byteLength)
                            }
                    }
                ).call(this)
            }
        ).call(this, e("buffer").Buffer)
    }
        , {
            "./assert.cjs": 9,
            "./hex.cjs": 18,
            "@scure/base": 191,
            buffer: 195
        }],
    12: [function(e, t, r) {
        "use strict";
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.toCaipAssetId = r.toCaipAssetType = r.toCaipAccountId = r.toCaipChainId = r.parseCaipAssetId = r.parseCaipAssetType = r.parseCaipAccountId = r.parseCaipChainId = r.isCaipAssetId = r.isCaipAssetType = r.isCaipTokenId = r.isCaipAssetReference = r.isCaipAssetNamespace = r.isCaipAccountAddress = r.isCaipAccountId = r.isCaipReference = r.isCaipNamespace = r.isCaipChainId = r.KnownCaipNamespace = r.CaipAssetTypeOrIdStruct = r.CaipAssetIdStruct = r.CaipAssetTypeStruct = r.CaipTokenIdStruct = r.CaipAssetReferenceStruct = r.CaipAssetNamespaceStruct = r.CaipAccountAddressStruct = r.CaipAccountIdStruct = r.CaipReferenceStruct = r.CaipNamespaceStruct = r.CaipChainIdStruct = r.CAIP_ASSET_ID_REGEX = r.CAIP_ASSET_TYPE_REGEX = r.CAIP_TOKEN_ID_REGEX = r.CAIP_ASSET_REFERENCE_REGEX = r.CAIP_ASSET_NAMESPACE_REGEX = r.CAIP_ACCOUNT_ADDRESS_REGEX = r.CAIP_ACCOUNT_ID_REGEX = r.CAIP_REFERENCE_REGEX = r.CAIP_NAMESPACE_REGEX = r.CAIP_CHAIN_ID_REGEX = void 0;
        const n = e("@metamask/superstruct")
            , s = e("./superstruct.cjs");
        r.CAIP_CHAIN_ID_REGEX = /^(?<namespace>[-a-z0-9]{3,8}):(?<reference>[-_a-zA-Z0-9]{1,32})$/u,
            r.CAIP_NAMESPACE_REGEX = /^[-a-z0-9]{3,8}$/u,
            r.CAIP_REFERENCE_REGEX = /^[-_a-zA-Z0-9]{1,32}$/u,
            r.CAIP_ACCOUNT_ID_REGEX = /^(?<chainId>(?<namespace>[-a-z0-9]{3,8}):(?<reference>[-_a-zA-Z0-9]{1,32})):(?<accountAddress>[-.%a-zA-Z0-9]{1,128})$/u,
            r.CAIP_ACCOUNT_ADDRESS_REGEX = /^[-.%a-zA-Z0-9]{1,128}$/u,
            r.CAIP_ASSET_NAMESPACE_REGEX = /^[-a-z0-9]{3,8}$/u,
            r.CAIP_ASSET_REFERENCE_REGEX = /^[-.%a-zA-Z0-9]{1,128}$/u,
            r.CAIP_TOKEN_ID_REGEX = /^[-.%a-zA-Z0-9]{1,78}$/u,
            r.CAIP_ASSET_TYPE_REGEX = /^(?<chainId>(?<namespace>[-a-z0-9]{3,8}):(?<reference>[-_a-zA-Z0-9]{1,32}))\/(?<assetNamespace>[-a-z0-9]{3,8}):(?<assetReference>[-.%a-zA-Z0-9]{1,128})$/u,
            r.CAIP_ASSET_ID_REGEX = /^(?<chainId>(?<namespace>[-a-z0-9]{3,8}):(?<reference>[-_a-zA-Z0-9]{1,32}))\/(?<assetNamespace>[-a-z0-9]{3,8}):(?<assetReference>[-.%a-zA-Z0-9]{1,128})\/(?<tokenId>[-.%a-zA-Z0-9]{1,78})$/u;
        function o(e) {
            return (0,
                n.is)(e, r.CaipNamespaceStruct)
        }
        function i(e) {
            return (0,
                n.is)(e, r.CaipReferenceStruct)
        }
        function a(e) {
            return (0,
                n.is)(e, r.CaipAccountAddressStruct)
        }
        function c(e) {
            return (0,
                n.is)(e, r.CaipAssetNamespaceStruct)
        }
        function u(e) {
            return (0,
                n.is)(e, r.CaipAssetReferenceStruct)
        }
        function l(e) {
            return (0,
                n.is)(e, r.CaipTokenIdStruct)
        }
        r.CaipChainIdStruct = (0,
            s.definePattern)("CaipChainId", r.CAIP_CHAIN_ID_REGEX),
            r.CaipNamespaceStruct = (0,
                s.definePattern)("CaipNamespace", r.CAIP_NAMESPACE_REGEX),
            r.CaipReferenceStruct = (0,
                s.definePattern)("CaipReference", r.CAIP_REFERENCE_REGEX),
            r.CaipAccountIdStruct = (0,
                s.definePattern)("CaipAccountId", r.CAIP_ACCOUNT_ID_REGEX),
            r.CaipAccountAddressStruct = (0,
                s.definePattern)("CaipAccountAddress", r.CAIP_ACCOUNT_ADDRESS_REGEX),
            r.CaipAssetNamespaceStruct = (0,
                s.definePattern)("CaipAssetNamespace", r.CAIP_ASSET_NAMESPACE_REGEX),
            r.CaipAssetReferenceStruct = (0,
                s.definePattern)("CaipAssetReference", r.CAIP_ASSET_REFERENCE_REGEX),
            r.CaipTokenIdStruct = (0,
                s.definePattern)("CaipTokenId", r.CAIP_TOKEN_ID_REGEX),
            r.CaipAssetTypeStruct = (0,
                s.definePattern)("CaipAssetType", r.CAIP_ASSET_TYPE_REGEX),
            r.CaipAssetIdStruct = (0,
                s.definePattern)("CaipAssetId", r.CAIP_ASSET_ID_REGEX),
            r.CaipAssetTypeOrIdStruct = (0,
                s.definePattern)("CaipAssetTypeOrId", /^(?<chainId>(?<namespace>[-a-z0-9]{3,8}):(?<reference>[-_a-zA-Z0-9]{1,32}))\/(?<assetNamespace>[-a-z0-9]{3,8}):(?<assetReference>[-.%a-zA-Z0-9]{1,128})(\/(?<tokenId>[-.%a-zA-Z0-9]{1,78}))?$/u),
            function(e) {
                e.Bip122 = "bip122",
                    e.Solana = "solana",
                    e.Eip155 = "eip155",
                    e.Wallet = "wallet"
            }(r.KnownCaipNamespace || (r.KnownCaipNamespace = {})),
            r.isCaipChainId = function(e) {
                return (0,
                    n.is)(e, r.CaipChainIdStruct)
            }
            ,
            r.isCaipNamespace = o,
            r.isCaipReference = i,
            r.isCaipAccountId = function(e) {
                return (0,
                    n.is)(e, r.CaipAccountIdStruct)
            }
            ,
            r.isCaipAccountAddress = a,
            r.isCaipAssetNamespace = c,
            r.isCaipAssetReference = u,
            r.isCaipTokenId = l,
            r.isCaipAssetType = function(e) {
                return (0,
                    n.is)(e, r.CaipAssetTypeStruct)
            }
            ,
            r.isCaipAssetId = function(e) {
                return (0,
                    n.is)(e, r.CaipAssetIdStruct)
            }
            ,
            r.parseCaipChainId = function(e) {
                const t = r.CAIP_CHAIN_ID_REGEX.exec(e);
                if (!t?.groups)
                    throw new Error("Invalid CAIP chain ID.");
                return {
                    namespace: t.groups.namespace,
                    reference: t.groups.reference
                }
            }
            ,
            r.parseCaipAccountId = function(e) {
                const t = r.CAIP_ACCOUNT_ID_REGEX.exec(e);
                if (!t?.groups)
                    throw new Error("Invalid CAIP account ID.");
                return {
                    address: t.groups.accountAddress,
                    chainId: t.groups.chainId,
                    chain: {
                        namespace: t.groups.namespace,
                        reference: t.groups.reference
                    }
                }
            }
            ,
            r.parseCaipAssetType = function(e) {
                const t = r.CAIP_ASSET_TYPE_REGEX.exec(e);
                if (!t?.groups)
                    throw new Error("Invalid CAIP asset type.");
                return {
                    assetNamespace: t.groups.assetNamespace,
                    assetReference: t.groups.assetReference,
                    chainId: t.groups.chainId,
                    chain: {
                        namespace: t.groups.namespace,
                        reference: t.groups.reference
                    }
                }
            }
            ,
            r.parseCaipAssetId = function(e) {
                const t = r.CAIP_ASSET_ID_REGEX.exec(e);
                if (!t?.groups)
                    throw new Error("Invalid CAIP asset ID.");
                return {
                    assetNamespace: t.groups.assetNamespace,
                    assetReference: t.groups.assetReference,
                    tokenId: t.groups.tokenId,
                    chainId: t.groups.chainId,
                    chain: {
                        namespace: t.groups.namespace,
                        reference: t.groups.reference
                    }
                }
            }
            ,
            r.toCaipChainId = function(e, t) {
                if (!o(e))
                    throw new Error(`Invalid "namespace", must match: ${r.CAIP_NAMESPACE_REGEX.toString()}`);
                if (!i(t))
                    throw new Error(`Invalid "reference", must match: ${r.CAIP_REFERENCE_REGEX.toString()}`);
                return `${e}:${t}`
            }
            ,
            r.toCaipAccountId = function(e, t, n) {
                if (!o(e))
                    throw new Error(`Invalid "namespace", must match: ${r.CAIP_NAMESPACE_REGEX.toString()}`);
                if (!i(t))
                    throw new Error(`Invalid "reference", must match: ${r.CAIP_REFERENCE_REGEX.toString()}`);
                if (!a(n))
                    throw new Error(`Invalid "accountAddress", must match: ${r.CAIP_ACCOUNT_ADDRESS_REGEX.toString()}`);
                return `${e}:${t}:${n}`
            }
            ,
            r.toCaipAssetType = function(e, t, n, s) {
                if (!o(e))
                    throw new Error(`Invalid "namespace", must match: ${r.CAIP_NAMESPACE_REGEX.toString()}`);
                if (!i(t))
                    throw new Error(`Invalid "reference", must match: ${r.CAIP_REFERENCE_REGEX.toString()}`);
                if (!c(n))
                    throw new Error(`Invalid "assetNamespace", must match: ${r.CAIP_ASSET_NAMESPACE_REGEX.toString()}`);
                if (!u(s))
                    throw new Error(`Invalid "assetReference", must match: ${r.CAIP_ASSET_REFERENCE_REGEX.toString()}`);
                return `${e}:${t}/${n}:${s}`
            }
            ,
            r.toCaipAssetId = function(e, t, n, s, a) {
                if (!o(e))
                    throw new Error(`Invalid "namespace", must match: ${r.CAIP_NAMESPACE_REGEX.toString()}`);
                if (!i(t))
                    throw new Error(`Invalid "reference", must match: ${r.CAIP_REFERENCE_REGEX.toString()}`);
                if (!c(n))
                    throw new Error(`Invalid "assetNamespace", must match: ${r.CAIP_ASSET_NAMESPACE_REGEX.toString()}`);
                if (!u(s))
                    throw new Error(`Invalid "assetReference", must match: ${r.CAIP_ASSET_REFERENCE_REGEX.toString()}`);
                if (!l(a))
                    throw new Error(`Invalid "tokenId", must match: ${r.CAIP_TOKEN_ID_REGEX.toString()}`);
                return `${e}:${t}/${n}:${s}/${a}`
            }
    }
        , {
            "./superstruct.cjs": 27,
            "@metamask/superstruct": 179
        }],
    13: [function(e, t, r) {
        "use strict";
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.ChecksumStruct = void 0;
        const n = e("@metamask/superstruct")
            , s = e("./base64.cjs");
        r.ChecksumStruct = (0,
            n.size)((0,
            s.base64)((0,
            n.string)(), {
            paddingRequired: !0
        }), 44, 44)
    }
        , {
            "./base64.cjs": 10,
            "@metamask/superstruct": 179
        }],
    14: [function(e, t, r) {
        "use strict";
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.createHex = r.createBytes = r.createBigInt = r.createNumber = void 0;
        const n = e("@metamask/superstruct")
            , s = e("./assert.cjs")
            , o = e("./bytes.cjs")
            , i = e("./hex.cjs")
            , a = (0,
            n.union)([(0,
            n.number)(), (0,
            n.bigint)(), (0,
            n.string)(), i.StrictHexStruct])
            , c = (0,
            n.coerce)((0,
            n.number)(), a, Number)
            , u = (0,
            n.coerce)((0,
            n.bigint)(), a, BigInt)
            , l = ((0,
            n.union)([i.StrictHexStruct, (0,
            n.instance)(Uint8Array)]),
            (0,
                n.coerce)((0,
                n.instance)(Uint8Array), (0,
                n.union)([i.StrictHexStruct]), o.hexToBytes))
            , d = (0,
            n.coerce)(i.StrictHexStruct, (0,
            n.instance)(Uint8Array), o.bytesToHex);
        r.createNumber = function(e) {
            try {
                const t = (0,
                    n.create)(e, c);
                return (0,
                    s.assert)(Number.isFinite(t), `Expected a number-like value, got "${e}".`),
                    t
            } catch (t) {
                if (t instanceof n.StructError)
                    throw new Error(`Expected a number-like value, got "${e}".`);
                throw t
            }
        }
            ,
            r.createBigInt = function(e) {
                try {
                    return (0,
                        n.create)(e, u)
                } catch (e) {
                    if (e instanceof n.StructError)
                        throw new Error(`Expected a number-like value, got "${String(e.value)}".`);
                    throw e
                }
            }
            ,
            r.createBytes = function(e) {
                if ("string" == typeof e && "0x" === e.toLowerCase())
                    return new Uint8Array;
                try {
                    return (0,
                        n.create)(e, l)
                } catch (e) {
                    if (e instanceof n.StructError)
                        throw new Error(`Expected a bytes-like value, got "${String(e.value)}".`);
                    throw e
                }
            }
            ,
            r.createHex = function(e) {
                if (e instanceof Uint8Array && 0 === e.length || "string" == typeof e && "0x" === e.toLowerCase())
                    return "0x";
                try {
                    return (0,
                        n.create)(e, d)
                } catch (e) {
                    if (e instanceof n.StructError)
                        throw new Error(`Expected a bytes-like value, got "${String(e.value)}".`);
                    throw e
                }
            }
    }
        , {
            "./assert.cjs": 9,
            "./bytes.cjs": 11,
            "./hex.cjs": 18,
            "@metamask/superstruct": 179
        }],
    15: [function(e, t, r) {
        "use strict";
        var n, s, o = this && this.__classPrivateFieldGet || function(e, t, r, n) {
                if ("a" === r && !n)
                    throw new TypeError("Private accessor was defined without a getter");
                if ("function" == typeof t ? e !== t || !n : !t.has(e))
                    throw new TypeError("Cannot read private member from an object whose class did not declare it");
                return "m" === r ? n : "a" === r ? n.call(e) : n ? n.value : t.get(e)
            }
            , i = this && this.__classPrivateFieldSet || function(e, t, r, n, s) {
                if ("m" === n)
                    throw new TypeError("Private method is not writable");
                if ("a" === n && !s)
                    throw new TypeError("Private accessor was defined without a setter");
                if ("function" == typeof t ? e !== t || !s : !t.has(e))
                    throw new TypeError("Cannot write private member to an object whose class did not declare it");
                return "a" === n ? s.call(e, r) : s ? s.value = r : t.set(e, r),
                    r
            }
        ;
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.FrozenSet = r.FrozenMap = void 0;
        class a {
            get size() {
                return o(this, n, "f").size
            }
            [(n = new WeakMap,
                Symbol.iterator)]() {
                return o(this, n, "f")[Symbol.iterator]()
            }
            constructor(e) {
                n.set(this, void 0),
                    i(this, n, new Map(e), "f"),
                    Object.freeze(this)
            }
            entries() {
                return o(this, n, "f").entries()
            }
            forEach(e, t) {
                return o(this, n, "f").forEach(( (r, n, s) => e.call(t, r, n, this)))
            }
            get(e) {
                return o(this, n, "f").get(e)
            }
            has(e) {
                return o(this, n, "f").has(e)
            }
            keys() {
                return o(this, n, "f").keys()
            }
            values() {
                return o(this, n, "f").values()
            }
            toString() {
                return `FrozenMap(${this.size}) {${this.size > 0 ? ` ${[...this.entries()].map(( ([e,t]) => `${String(e)} => ${String(t)}`)).join(", ")} ` : ""}}`
            }
        }
        r.FrozenMap = a;
        class c {
            get size() {
                return o(this, s, "f").size
            }
            [(s = new WeakMap,
                Symbol.iterator)]() {
                return o(this, s, "f")[Symbol.iterator]()
            }
            constructor(e) {
                s.set(this, void 0),
                    i(this, s, new Set(e), "f"),
                    Object.freeze(this)
            }
            entries() {
                return o(this, s, "f").entries()
            }
            forEach(e, t) {
                return o(this, s, "f").forEach(( (r, n, s) => e.call(t, r, n, this)))
            }
            has(e) {
                return o(this, s, "f").has(e)
            }
            keys() {
                return o(this, s, "f").keys()
            }
            values() {
                return o(this, s, "f").values()
            }
            toString() {
                return `FrozenSet(${this.size}) {${this.size > 0 ? ` ${[...this.values()].map((e => String(e))).join(", ")} ` : ""}}`
            }
        }
        r.FrozenSet = c,
            Object.freeze(a),
            Object.freeze(a.prototype),
            Object.freeze(c),
            Object.freeze(c.prototype)
    }
        , {}],
    16: [function(e, t, r) {
        "use strict";
        Object.defineProperty(r, "__esModule", {
            value: !0
        })
    }
        , {}],
    17: [function(e, t, r) {
        "use strict";
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.wrapError = r.getErrorMessage = r.isErrorWithStack = r.isErrorWithMessage = r.isErrorWithCode = void 0;
        const n = e("pony-cause")
            , s = e("./misc.cjs");
        function o(e) {
            return "object" == typeof e && null !== e && "code"in e
        }
        function i(e) {
            return "object" == typeof e && null !== e && "message"in e
        }
        r.isErrorWithCode = o,
            r.isErrorWithMessage = i,
            r.isErrorWithStack = function(e) {
                return "object" == typeof e && null !== e && "stack"in e
            }
            ,
            r.getErrorMessage = function(e) {
                return i(e) && "string" == typeof e.message ? e.message : (0,
                    s.isNullOrUndefined)(e) ? "" : String(e)
            }
            ,
            r.wrapError = function(e, t) {
                if ((r = e)instanceof Error || (0,
                    s.isObject)(r) && "Error" === r.constructor.name) {
                    let r;
                    return r = 2 === Error.length ? new Error(t,{
                        cause: e
                    }) : new n.ErrorWithCause(t,{
                        cause: e
                    }),
                    o(e) && (r.code = e.code),
                        r
                }
                var r;
                return t.length > 0 ? new Error(`${String(e)}: ${t}`) : new Error(String(e))
            }
    }
        , {
            "./misc.cjs": 23,
            "pony-cause": 208
        }],
    18: [function(e, t, r) {
        "use strict";
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.remove0x = r.add0x = r.isValidChecksumAddress = r.getChecksumAddress = r.isValidHexAddress = r.assertIsStrictHexString = r.assertIsHexString = r.isStrictHexString = r.isHexString = r.HexChecksumAddressStruct = r.HexAddressStruct = r.StrictHexStruct = r.HexStruct = void 0;
        const n = e("@metamask/superstruct")
            , s = e("@noble/hashes/sha3")
            , o = e("./assert.cjs")
            , i = e("./bytes.cjs");
        function a(e) {
            return (0,
                n.is)(e, r.HexStruct)
        }
        function c(e) {
            return (0,
                n.is)(e, r.StrictHexStruct)
        }
        function u(e) {
            (0,
                o.assert)((0,
                n.is)(e, r.HexChecksumAddressStruct), "Invalid hex address.");
            const t = d(e.toLowerCase())
                , a = d((0,
                i.bytesToHex)((0,
                s.keccak_256)(t)));
            return `0x${t.split("").map(( (e, t) => {
                    const r = a[t];
                    return (0,
                        o.assert)((0,
                        n.is)(r, (0,
                        n.string)()), "Hash shorter than address."),
                        parseInt(r, 16) > 7 ? e.toUpperCase() : e
                }
            )).join("")}`
        }
        function l(e) {
            return !!(0,
                n.is)(e, r.HexChecksumAddressStruct) && u(e) === e
        }
        function d(e) {
            return e.startsWith("0x") || e.startsWith("0X") ? e.substring(2) : e
        }
        r.HexStruct = (0,
            n.pattern)((0,
            n.string)(), /^(?:0x)?[0-9a-f]+$/iu),
            r.StrictHexStruct = (0,
                n.pattern)((0,
                n.string)(), /^0x[0-9a-f]+$/iu),
            r.HexAddressStruct = (0,
                n.pattern)((0,
                n.string)(), /^0x[0-9a-f]{40}$/u),
            r.HexChecksumAddressStruct = (0,
                n.pattern)((0,
                n.string)(), /^0x[0-9a-fA-F]{40}$/u),
            r.isHexString = a,
            r.isStrictHexString = c,
            r.assertIsHexString = function(e) {
                (0,
                    o.assert)(a(e), "Value must be a hexadecimal string.")
            }
            ,
            r.assertIsStrictHexString = function(e) {
                (0,
                    o.assert)(c(e), 'Value must be a hexadecimal string, starting with "0x".')
            }
            ,
            r.isValidHexAddress = function(e) {
                return (0,
                    n.is)(e, r.HexAddressStruct) || l(e)
            }
            ,
            r.getChecksumAddress = u,
            r.isValidChecksumAddress = l,
            r.add0x = function(e) {
                return e.startsWith("0x") ? e : e.startsWith("0X") ? `0x${e.substring(2)}` : `0x${e}`
            }
            ,
            r.remove0x = d
    }
        , {
            "./assert.cjs": 9,
            "./bytes.cjs": 11,
            "@metamask/superstruct": 179,
            "@noble/hashes/sha3": 189
        }],
    19: [function(e, t, r) {
        "use strict";
        var n = this && this.__createBinding || (Object.create ? function(e, t, r, n) {
                        void 0 === n && (n = r);
                        var s = Object.getOwnPropertyDescriptor(t, r);
                        s && !("get"in s ? !t.__esModule : s.writable || s.configurable) || (s = {
                            enumerable: !0,
                            get: function() {
                                return t[r]
                            }
                        }),
                            Object.defineProperty(e, n, s)
                    }
                    : function(e, t, r, n) {
                        void 0 === n && (n = r),
                            e[n] = t[r]
                    }
            )
            , s = this && this.__exportStar || function(e, t) {
                for (var r in e)
                    "default" === r || Object.prototype.hasOwnProperty.call(t, r) || n(t, e, r)
            }
        ;
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            s(e("./assert.cjs"), r),
            s(e("./base64.cjs"), r),
            s(e("./bytes.cjs"), r),
            s(e("./caip-types.cjs"), r),
            s(e("./checksum.cjs"), r),
            s(e("./coercers.cjs"), r),
            s(e("./collections.cjs"), r),
            s(e("./encryption-types.cjs"), r),
            s(e("./errors.cjs"), r),
            s(e("./hex.cjs"), r),
            s(e("./json.cjs"), r),
            s(e("./keyring.cjs"), r),
            s(e("./logging.cjs"), r),
            s(e("./misc.cjs"), r),
            s(e("./number.cjs"), r),
            s(e("./opaque.cjs"), r),
            s(e("./promise.cjs"), r),
            s(e("./superstruct.cjs"), r),
            s(e("./time.cjs"), r),
            s(e("./transaction-types.cjs"), r),
            s(e("./versions.cjs"), r)
    }
        , {
            "./assert.cjs": 9,
            "./base64.cjs": 10,
            "./bytes.cjs": 11,
            "./caip-types.cjs": 12,
            "./checksum.cjs": 13,
            "./coercers.cjs": 14,
            "./collections.cjs": 15,
            "./encryption-types.cjs": 16,
            "./errors.cjs": 17,
            "./hex.cjs": 18,
            "./json.cjs": 20,
            "./keyring.cjs": 21,
            "./logging.cjs": 22,
            "./misc.cjs": 23,
            "./number.cjs": 24,
            "./opaque.cjs": 25,
            "./promise.cjs": 26,
            "./superstruct.cjs": 27,
            "./time.cjs": 28,
            "./transaction-types.cjs": 29,
            "./versions.cjs": 30
        }],
    20: [function(e, t, r) {
        "use strict";
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.getJsonRpcIdValidator = r.assertIsJsonRpcError = r.isJsonRpcError = r.assertIsJsonRpcFailure = r.isJsonRpcFailure = r.assertIsJsonRpcSuccess = r.isJsonRpcSuccess = r.assertIsJsonRpcResponse = r.isJsonRpcResponse = r.assertIsPendingJsonRpcResponse = r.isPendingJsonRpcResponse = r.JsonRpcResponseStruct = r.JsonRpcFailureStruct = r.JsonRpcSuccessStruct = r.PendingJsonRpcResponseStruct = r.assertIsJsonRpcRequest = r.isJsonRpcRequest = r.assertIsJsonRpcNotification = r.isJsonRpcNotification = r.JsonRpcNotificationStruct = r.JsonRpcRequestStruct = r.JsonRpcParamsStruct = r.JsonRpcErrorStruct = r.JsonRpcIdStruct = r.JsonRpcVersionStruct = r.jsonrpc2 = r.getJsonSize = r.getSafeJson = r.isValidJson = r.JsonStruct = r.UnsafeJsonStruct = r.exactOptional = r.object = void 0;
        const n = e("@metamask/superstruct")
            , s = e("./assert.cjs")
            , o = e("./misc.cjs");
        function i({path: e, branch: t}) {
            const r = e[e.length - 1];
            return (0,
                o.hasProperty)(t[t.length - 2], r)
        }
        function a(e) {
            return new n.Struct({
                ...e,
                type: `optional ${e.type}`,
                validator: (t, r) => !i(r) || e.validator(t, r),
                refiner: (t, r) => !i(r) || e.refiner(t, r)
            })
        }
        function c(e) {
            if (null === e || "boolean" == typeof e || "string" == typeof e)
                return !0;
            if ("number" == typeof e && Number.isFinite(e))
                return !0;
            if ("object" == typeof e) {
                let t = !0;
                if (Array.isArray(e)) {
                    for (let r = 0; r < e.length; r++)
                        if (!c(e[r])) {
                            t = !1;
                            break
                        }
                    return t
                }
                const r = Object.entries(e);
                for (let e = 0; e < r.length; e++)
                    if ("string" != typeof r[e][0] || !c(r[e][1])) {
                        t = !1;
                        break
                    }
                return t
            }
            return !1
        }
        function u(e) {
            return (0,
                n.create)(e, r.JsonStruct)
        }
        r.object = e => (0,
            n.object)(e),
            r.exactOptional = a,
            r.UnsafeJsonStruct = (0,
                n.define)("JSON", (e => c(e))),
            r.JsonStruct = (0,
                n.coerce)(r.UnsafeJsonStruct, (0,
                n.refine)((0,
                n.any)(), "JSON", (e => (0,
                n.is)(e, r.UnsafeJsonStruct))), (e => JSON.parse(JSON.stringify(e, ( (e, t) => {
                    if ("__proto__" !== e && "constructor" !== e)
                        return t
                }
            ))))),
            r.isValidJson = function(e) {
                try {
                    return u(e),
                        !0
                } catch {
                    return !1
                }
            }
            ,
            r.getSafeJson = u,
            r.getJsonSize = function(e) {
                (0,
                    s.assertStruct)(e, r.JsonStruct, "Invalid JSON value");
                const t = JSON.stringify(e);
                return (new TextEncoder).encode(t).byteLength
            }
            ,
            r.jsonrpc2 = "2.0",
            r.JsonRpcVersionStruct = (0,
                n.literal)(r.jsonrpc2),
            r.JsonRpcIdStruct = (0,
                n.nullable)((0,
                n.union)([(0,
                n.number)(), (0,
                n.string)()])),
            r.JsonRpcErrorStruct = (0,
                r.object)({
                code: (0,
                    n.integer)(),
                message: (0,
                    n.string)(),
                data: a(r.JsonStruct),
                stack: a((0,
                    n.string)())
            }),
            r.JsonRpcParamsStruct = (0,
                n.union)([(0,
                n.record)((0,
                n.string)(), r.JsonStruct), (0,
                n.array)(r.JsonStruct)]),
            r.JsonRpcRequestStruct = (0,
                r.object)({
                id: r.JsonRpcIdStruct,
                jsonrpc: r.JsonRpcVersionStruct,
                method: (0,
                    n.string)(),
                params: a(r.JsonRpcParamsStruct)
            }),
            r.JsonRpcNotificationStruct = (0,
                r.object)({
                jsonrpc: r.JsonRpcVersionStruct,
                method: (0,
                    n.string)(),
                params: a(r.JsonRpcParamsStruct)
            }),
            r.isJsonRpcNotification = function(e) {
                return (0,
                    n.is)(e, r.JsonRpcNotificationStruct)
            }
            ,
            r.assertIsJsonRpcNotification = function(e, t) {
                (0,
                    s.assertStruct)(e, r.JsonRpcNotificationStruct, "Invalid JSON-RPC notification", t)
            }
            ,
            r.isJsonRpcRequest = function(e) {
                return (0,
                    n.is)(e, r.JsonRpcRequestStruct)
            }
            ,
            r.assertIsJsonRpcRequest = function(e, t) {
                (0,
                    s.assertStruct)(e, r.JsonRpcRequestStruct, "Invalid JSON-RPC request", t)
            }
            ,
            r.PendingJsonRpcResponseStruct = (0,
                n.object)({
                id: r.JsonRpcIdStruct,
                jsonrpc: r.JsonRpcVersionStruct,
                result: (0,
                    n.optional)((0,
                    n.unknown)()),
                error: (0,
                    n.optional)(r.JsonRpcErrorStruct)
            }),
            r.JsonRpcSuccessStruct = (0,
                r.object)({
                id: r.JsonRpcIdStruct,
                jsonrpc: r.JsonRpcVersionStruct,
                result: r.JsonStruct
            }),
            r.JsonRpcFailureStruct = (0,
                r.object)({
                id: r.JsonRpcIdStruct,
                jsonrpc: r.JsonRpcVersionStruct,
                error: r.JsonRpcErrorStruct
            }),
            r.JsonRpcResponseStruct = (0,
                n.union)([r.JsonRpcSuccessStruct, r.JsonRpcFailureStruct]),
            r.isPendingJsonRpcResponse = function(e) {
                return (0,
                    n.is)(e, r.PendingJsonRpcResponseStruct)
            }
            ,
            r.assertIsPendingJsonRpcResponse = function(e, t) {
                (0,
                    s.assertStruct)(e, r.PendingJsonRpcResponseStruct, "Invalid pending JSON-RPC response", t)
            }
            ,
            r.isJsonRpcResponse = function(e) {
                return (0,
                    n.is)(e, r.JsonRpcResponseStruct)
            }
            ,
            r.assertIsJsonRpcResponse = function(e, t) {
                (0,
                    s.assertStruct)(e, r.JsonRpcResponseStruct, "Invalid JSON-RPC response", t)
            }
            ,
            r.isJsonRpcSuccess = function(e) {
                return (0,
                    n.is)(e, r.JsonRpcSuccessStruct)
            }
            ,
            r.assertIsJsonRpcSuccess = function(e, t) {
                (0,
                    s.assertStruct)(e, r.JsonRpcSuccessStruct, "Invalid JSON-RPC success response", t)
            }
            ,
            r.isJsonRpcFailure = function(e) {
                return (0,
                    n.is)(e, r.JsonRpcFailureStruct)
            }
            ,
            r.assertIsJsonRpcFailure = function(e, t) {
                (0,
                    s.assertStruct)(e, r.JsonRpcFailureStruct, "Invalid JSON-RPC failure response", t)
            }
            ,
            r.isJsonRpcError = function(e) {
                return (0,
                    n.is)(e, r.JsonRpcErrorStruct)
            }
            ,
            r.assertIsJsonRpcError = function(e, t) {
                (0,
                    s.assertStruct)(e, r.JsonRpcErrorStruct, "Invalid JSON-RPC error", t)
            }
            ,
            r.getJsonRpcIdValidator = function(e) {
                const {permitEmptyString: t, permitFractions: r, permitNull: n} = {
                    permitEmptyString: !0,
                    permitFractions: !1,
                    permitNull: !0,
                    ...e
                };
                return e => Boolean("number" == typeof e && (r || Number.isInteger(e)) || "string" == typeof e && (t || e.length > 0) || n && null === e)
            }
    }
        , {
            "./assert.cjs": 9,
            "./misc.cjs": 23,
            "@metamask/superstruct": 179
        }],
    21: [function(e, t, r) {
        "use strict";
        Object.defineProperty(r, "__esModule", {
            value: !0
        })
    }
        , {}],
    22: [function(e, t, r) {
        "use strict";
        var n = this && this.__importDefault || function(e) {
                return e && e.__esModule ? e : {
                    default: e
                }
            }
        ;
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.createModuleLogger = r.createProjectLogger = void 0;
        const s = (0,
            n(e("debug")).default)("metamask");
        r.createProjectLogger = function(e) {
            return s.extend(e)
        }
            ,
            r.createModuleLogger = function(e, t) {
                return e.extend(t)
            }
    }
        , {
            debug: 197
        }],
    23: [function(e, t, r) {
        "use strict";
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.calculateNumberSize = r.calculateStringSize = r.isASCII = r.isPlainObject = r.ESCAPE_CHARACTERS_REGEXP = r.JsonSize = r.getKnownPropertyNames = r.hasProperty = r.isObject = r.isNullOrUndefined = r.isNonEmptyArray = void 0,
            r.isNonEmptyArray = function(e) {
                return Array.isArray(e) && e.length > 0
            }
            ,
            r.isNullOrUndefined = function(e) {
                return null == e
            }
            ,
            r.isObject = function(e) {
                return Boolean(e) && "object" == typeof e && !Array.isArray(e)
            }
        ;
        function n(e) {
            return e.charCodeAt(0) <= 127
        }
        r.hasProperty = (e, t) => Object.hasOwnProperty.call(e, t),
            r.getKnownPropertyNames = function(e) {
                return Object.getOwnPropertyNames(e)
            }
            ,
            function(e) {
                e[e.Null = 4] = "Null",
                    e[e.Comma = 1] = "Comma",
                    e[e.Wrapper = 1] = "Wrapper",
                    e[e.True = 4] = "True",
                    e[e.False = 5] = "False",
                    e[e.Quote = 1] = "Quote",
                    e[e.Colon = 1] = "Colon",
                    e[e.Date = 24] = "Date"
            }(r.JsonSize || (r.JsonSize = {})),
            r.ESCAPE_CHARACTERS_REGEXP = /"|\\|\n|\r|\t/gu,
            r.isPlainObject = function(e) {
                if ("object" != typeof e || null === e)
                    return !1;
                try {
                    let t = e;
                    for (; null !== Object.getPrototypeOf(t); )
                        t = Object.getPrototypeOf(t);
                    return Object.getPrototypeOf(e) === t
                } catch (e) {
                    return !1
                }
            }
            ,
            r.isASCII = n,
            r.calculateStringSize = function(e) {
                return e.split("").reduce(( (e, t) => n(t) ? e + 1 : e + 2), 0) + (e.match(r.ESCAPE_CHARACTERS_REGEXP) ?? []).length
            }
            ,
            r.calculateNumberSize = function(e) {
                return e.toString().length
            }
    }
        , {}],
    24: [function(e, t, r) {
        "use strict";
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.hexToBigInt = r.hexToNumber = r.bigIntToHex = r.numberToHex = void 0;
        const n = e("./assert.cjs")
            , s = e("./hex.cjs");
        r.numberToHex = e => ((0,
            n.assert)("number" == typeof e, "Value must be a number."),
            (0,
                n.assert)(e >= 0, "Value must be a non-negative number."),
            (0,
                n.assert)(Number.isSafeInteger(e), "Value is not a safe integer. Use `bigIntToHex` instead."),
            (0,
                s.add0x)(e.toString(16)));
        r.bigIntToHex = e => ((0,
            n.assert)("bigint" == typeof e, "Value must be a bigint."),
            (0,
                n.assert)(e >= 0, "Value must be a non-negative bigint."),
            (0,
                s.add0x)(e.toString(16)));
        r.hexToNumber = e => {
            (0,
                s.assertIsHexString)(e);
            const t = parseInt(e, 16);
            return (0,
                n.assert)(Number.isSafeInteger(t), "Value is not a safe integer. Use `hexToBigInt` instead."),
                t
        }
        ;
        r.hexToBigInt = e => ((0,
            s.assertIsHexString)(e),
            BigInt((0,
                s.add0x)(e)))
    }
        , {
            "./assert.cjs": 9,
            "./hex.cjs": 18
        }],
    25: [function(e, t, r) {
        "use strict";
        Object.defineProperty(r, "__esModule", {
            value: !0
        })
    }
        , {}],
    26: [function(e, t, r) {
        "use strict";
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.createDeferredPromise = void 0,
            r.createDeferredPromise = function({suppressUnhandledRejection: e=!1}={}) {
                let t, r;
                const n = new Promise(( (e, n) => {
                        t = e,
                            r = n
                    }
                ));
                return e && n.catch((e => {}
                )),
                    {
                        promise: n,
                        resolve: t,
                        reject: r
                    }
            }
    }
        , {}],
    27: [function(e, t, r) {
        "use strict";
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.definePattern = void 0;
        const n = e("@metamask/superstruct");
        r.definePattern = function(e, t) {
            return (0,
                n.define)(e, (e => "string" == typeof e && t.test(e)))
        }
    }
        , {
            "@metamask/superstruct": 179
        }],
    28: [function(e, t, r) {
        "use strict";
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.timeSince = r.inMilliseconds = r.Duration = void 0,
            function(e) {
                e[e.Millisecond = 1] = "Millisecond",
                    e[e.Second = 1e3] = "Second",
                    e[e.Minute = 6e4] = "Minute",
                    e[e.Hour = 36e5] = "Hour",
                    e[e.Day = 864e5] = "Day",
                    e[e.Week = 6048e5] = "Week",
                    e[e.Year = 31536e6] = "Year"
            }(r.Duration || (r.Duration = {}));
        const n = (e, t) => {
                if (!(e => Number.isInteger(e) && e >= 0)(e))
                    throw new Error(`"${t}" must be a non-negative integer. Received: "${e}".`)
            }
        ;
        r.inMilliseconds = function(e, t) {
            return n(e, "count"),
            e * t
        }
            ,
            r.timeSince = function(e) {
                return n(e, "timestamp"),
                Date.now() - e
            }
    }
        , {}],
    29: [function(e, t, r) {
        "use strict";
        Object.defineProperty(r, "__esModule", {
            value: !0
        })
    }
        , {}],
    30: [function(e, t, r) {
        "use strict";
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.satisfiesVersionRange = r.gtRange = r.gtVersion = r.assertIsSemVerRange = r.assertIsSemVerVersion = r.isValidSemVerRange = r.isValidSemVerVersion = r.VersionRangeStruct = r.VersionStruct = void 0;
        const n = e("@metamask/superstruct")
            , s = e("semver")
            , o = e("./assert.cjs");
        r.VersionStruct = (0,
            n.refine)((0,
            n.string)(), "Version", (e => null !== (0,
            s.valid)(e) || `Expected SemVer version, got "${e}"`)),
            r.VersionRangeStruct = (0,
                n.refine)((0,
                n.string)(), "Version range", (e => null !== (0,
                s.validRange)(e) || `Expected SemVer range, got "${e}"`)),
            r.isValidSemVerVersion = function(e) {
                return (0,
                    n.is)(e, r.VersionStruct)
            }
            ,
            r.isValidSemVerRange = function(e) {
                return (0,
                    n.is)(e, r.VersionRangeStruct)
            }
            ,
            r.assertIsSemVerVersion = function(e) {
                (0,
                    o.assertStruct)(e, r.VersionStruct)
            }
            ,
            r.assertIsSemVerRange = function(e) {
                (0,
                    o.assertStruct)(e, r.VersionRangeStruct)
            }
            ,
            r.gtVersion = function(e, t) {
                return (0,
                    s.gt)(e, t)
            }
            ,
            r.gtRange = function(e, t) {
                return (0,
                    s.gtr)(e, t)
            }
            ,
            r.satisfiesVersionRange = function(e, t) {
                return (0,
                    s.satisfies)(e, t, {
                    includePrerelease: !0
                })
            }
    }
        , {
            "./assert.cjs": 9,
            "@metamask/superstruct": 179,
            semver: 255
        }],
    31: [function(e, t, r) {
        "use strict";
        Object.defineProperty(r, "__esModule", {
            value: !0
        });
        const n = e("readable-stream");
        r.default = function(e) {
            if (!e?.engine)
                throw new Error("Missing engine parameter!");
            const {engine: t} = e
                , r = new n.Duplex({
                objectMode: !0,
                read: () => {}
                ,
                write: function(e, n, s) {
                    t.handle(e, ( (e, t) => {
                            r.push(t)
                        }
                    )),
                        s()
                }
            });
            return t.on && t.on("notification", (e => {
                    r.push(e)
                }
            )),
                r
        }
    }
        , {
            "readable-stream": 226
        }],
    32: [function(e, t, r) {
        "use strict";
        var n = this && this.__importDefault || function(e) {
                return e && e.__esModule ? e : {
                    default: e
                }
            }
        ;
        Object.defineProperty(r, "__esModule", {
            value: !0
        });
        const s = n(e("@metamask/safe-event-emitter"))
            , o = e("@metamask/utils")
            , i = e("readable-stream");
        r.default = function(e={}) {
            const t = {}
                , r = new i.Duplex({
                objectMode: !0,
                read: () => {}
                ,
                write: function(r, s, i) {
                    let c = null;
                    try {
                        !(0,
                            o.hasProperty)(r, "id") ? function(r) {
                            e?.retryOnMessage && r.method === e.retryOnMessage && Object.values(t).forEach(( ({req: e, retryCount: r=0}) => {
                                    if (!e.id)
                                        return;
                                    if (r >= 3)
                                        throw new Error(`StreamMiddleware - Retry limit exceeded for request id "${e.id}"`);
                                    const n = t[e.id];
                                    n && (n.retryCount = r + 1),
                                        a(e)
                                }
                            ));
                            n.emit("notification", r)
                        }(r) : function(e) {
                            const {id: r} = e;
                            if (null === r)
                                return;
                            const n = t[r];
                            if (!n)
                                return void console.warn(`StreamMiddleware - Unknown response id "${r}"`);
                            delete t[r],
                                Object.assign(n.res, e),
                                setTimeout(n.end)
                        }(r)
                    } catch (e) {
                        c = e
                    }
                    i(c)
                }
            })
                , n = new s.default;
            return {
                events: n,
                middleware: (e, r, n, s) => {
                    t[e.id] = {
                        req: e,
                        res: r,
                        next: n,
                        end: s
                    },
                        a(e)
                }
                ,
                stream: r
            };
            function a(e) {
                r.push(e)
            }
        }
    }
        , {
            "@metamask/safe-event-emitter": 177,
            "@metamask/utils": 44,
            "readable-stream": 226
        }],
    33: [function(e, t, r) {
        "use strict";
        var n = this && this.__importDefault || function(e) {
                return e && e.__esModule ? e : {
                    default: e
                }
            }
        ;
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.createStreamMiddleware = r.createEngineStream = void 0;
        const s = n(e("./createEngineStream.cjs"));
        r.createEngineStream = s.default;
        const o = n(e("./createStreamMiddleware.cjs"));
        r.createStreamMiddleware = o.default
    }
        , {
            "./createEngineStream.cjs": 31,
            "./createStreamMiddleware.cjs": 32
        }],
    34: [function(e, t, r) {
        arguments[4][9][0].apply(r, arguments)
    }
        , {
            "./errors.cjs": 42,
            "@metamask/superstruct": 179,
            dup: 9
        }],
    35: [function(e, t, r) {
        arguments[4][10][0].apply(r, arguments)
    }
        , {
            "./assert.cjs": 34,
            "@metamask/superstruct": 179,
            dup: 10
        }],
    36: [function(e, t, r) {
        (function(t) {
                (function() {
                        "use strict";
                        Object.defineProperty(r, "__esModule", {
                            value: !0
                        }),
                            r.createDataView = r.concatBytes = r.valueToBytes = r.base64ToBytes = r.stringToBytes = r.numberToBytes = r.signedBigIntToBytes = r.bigIntToBytes = r.hexToBytes = r.bytesToBase64 = r.bytesToString = r.bytesToNumber = r.bytesToSignedBigInt = r.bytesToBigInt = r.bytesToHex = r.assertIsBytes = r.isBytes = void 0;
                        const n = e("@scure/base")
                            , s = e("./assert.cjs")
                            , o = e("./hex.cjs")
                            , i = 48
                            , a = 58
                            , c = 87;
                        const u = function() {
                            const e = [];
                            return () => {
                                if (0 === e.length)
                                    for (let t = 0; t < 256; t++)
                                        e.push(t.toString(16).padStart(2, "0"));
                                return e
                            }
                        }();
                        function l(e) {
                            return e instanceof Uint8Array
                        }
                        function d(e) {
                            (0,
                                s.assert)(l(e), "Value must be a Uint8Array.")
                        }
                        function f(e) {
                            if (d(e),
                            0 === e.length)
                                return "0x";
                            const t = u()
                                , r = new Array(e.length);
                            for (let n = 0; n < e.length; n++)
                                r[n] = t[e[n]];
                            return (0,
                                o.add0x)(r.join(""))
                        }
                        function p(e) {
                            d(e);
                            const t = f(e);
                            return BigInt(t)
                        }
                        function h(e) {
                            if ("0x" === e?.toLowerCase?.())
                                return new Uint8Array;
                            (0,
                                o.assertIsHexString)(e);
                            const t = (0,
                                o.remove0x)(e).toLowerCase()
                                , r = t.length % 2 == 0 ? t : `0${t}`
                                , n = new Uint8Array(r.length / 2);
                            for (let e = 0; e < n.length; e++) {
                                const t = r.charCodeAt(2 * e)
                                    , s = r.charCodeAt(2 * e + 1)
                                    , o = t - (t < a ? i : c)
                                    , u = s - (s < a ? i : c);
                                n[e] = 16 * o + u
                            }
                            return n
                        }
                        function g(e) {
                            (0,
                                s.assert)("bigint" == typeof e, "Value must be a bigint."),
                                (0,
                                    s.assert)(e >= BigInt(0), "Value must be a non-negative bigint.");
                            return h(e.toString(16))
                        }
                        function m(e) {
                            (0,
                                s.assert)("number" == typeof e, "Value must be a number."),
                                (0,
                                    s.assert)(e >= 0, "Value must be a non-negative number."),
                                (0,
                                    s.assert)(Number.isSafeInteger(e), "Value is not a safe integer. Use `bigIntToBytes` instead.");
                            return h(e.toString(16))
                        }
                        function b(e) {
                            return (0,
                                s.assert)("string" == typeof e, "Value must be a string."),
                                (new TextEncoder).encode(e)
                        }
                        function y(e) {
                            if ("bigint" == typeof e)
                                return g(e);
                            if ("number" == typeof e)
                                return m(e);
                            if ("string" == typeof e)
                                return e.startsWith("0x") ? h(e) : b(e);
                            if (l(e))
                                return e;
                            throw new TypeError(`Unsupported value type: "${typeof e}".`)
                        }
                        r.isBytes = l,
                            r.assertIsBytes = d,
                            r.bytesToHex = f,
                            r.bytesToBigInt = p,
                            r.bytesToSignedBigInt = function(e) {
                                d(e);
                                let t = BigInt(0);
                                for (const r of e)
                                    t = (t << BigInt(8)) + BigInt(r);
                                return BigInt.asIntN(8 * e.length, t)
                            }
                            ,
                            r.bytesToNumber = function(e) {
                                d(e);
                                const t = p(e);
                                return (0,
                                    s.assert)(t <= BigInt(Number.MAX_SAFE_INTEGER), "Number is not a safe integer. Use `bytesToBigInt` instead."),
                                    Number(t)
                            }
                            ,
                            r.bytesToString = function(e) {
                                return d(e),
                                    (new TextDecoder).decode(e)
                            }
                            ,
                            r.bytesToBase64 = function(e) {
                                return d(e),
                                    n.base64.encode(e)
                            }
                            ,
                            r.hexToBytes = h,
                            r.bigIntToBytes = g,
                            r.signedBigIntToBytes = function(e, t) {
                                (0,
                                    s.assert)("bigint" == typeof e, "Value must be a bigint."),
                                    (0,
                                        s.assert)("number" == typeof t, "Byte length must be a number."),
                                    (0,
                                        s.assert)(t > 0, "Byte length must be greater than 0."),
                                    (0,
                                        s.assert)(function(e, t) {
                                        (0,
                                            s.assert)(t > 0);
                                        const r = e >> BigInt(31);
                                        return !((~e & r) + (e & ~r) >> BigInt(8 * t - 1))
                                    }(e, t), "Byte length is too small to represent the given value.");
                                let r = e;
                                const n = new Uint8Array(t);
                                for (let e = 0; e < n.length; e++)
                                    n[e] = Number(BigInt.asUintN(8, r)),
                                        r >>= BigInt(8);
                                return n.reverse()
                            }
                            ,
                            r.numberToBytes = m,
                            r.stringToBytes = b,
                            r.base64ToBytes = function(e) {
                                return (0,
                                    s.assert)("string" == typeof e, "Value must be a string."),
                                    n.base64.decode(e)
                            }
                            ,
                            r.valueToBytes = y,
                            r.concatBytes = function(e) {
                                const t = new Array(e.length);
                                let r = 0;
                                for (let n = 0; n < e.length; n++) {
                                    const s = y(e[n]);
                                    t[n] = s,
                                        r += s.length
                                }
                                const n = new Uint8Array(r);
                                for (let e = 0, r = 0; e < t.length; e++)
                                    n.set(t[e], r),
                                        r += t[e].length;
                                return n
                            }
                            ,
                            r.createDataView = function(e) {
                                if (void 0 !== t && e instanceof t) {
                                    const t = e.buffer.slice(e.byteOffset, e.byteOffset + e.byteLength);
                                    return new DataView(t)
                                }
                                return new DataView(e.buffer,e.byteOffset,e.byteLength)
                            }
                    }
                ).call(this)
            }
        ).call(this, e("buffer").Buffer)
    }
        , {
            "./assert.cjs": 34,
            "./hex.cjs": 43,
            "@scure/base": 191,
            buffer: 195
        }],
    37: [function(e, t, r) {
        arguments[4][12][0].apply(r, arguments)
    }
        , {
            "./superstruct.cjs": 52,
            "@metamask/superstruct": 179,
            dup: 12
        }],
    38: [function(e, t, r) {
        arguments[4][13][0].apply(r, arguments)
    }
        , {
            "./base64.cjs": 35,
            "@metamask/superstruct": 179,
            dup: 13
        }],
    39: [function(e, t, r) {
        arguments[4][14][0].apply(r, arguments)
    }
        , {
            "./assert.cjs": 34,
            "./bytes.cjs": 36,
            "./hex.cjs": 43,
            "@metamask/superstruct": 179,
            dup: 14
        }],
    40: [function(e, t, r) {
        arguments[4][15][0].apply(r, arguments)
    }
        , {
            dup: 15
        }],
    41: [function(e, t, r) {
        arguments[4][16][0].apply(r, arguments)
    }
        , {
            dup: 16
        }],
    42: [function(e, t, r) {
        arguments[4][17][0].apply(r, arguments)
    }
        , {
            "./misc.cjs": 48,
            dup: 17,
            "pony-cause": 208
        }],
    43: [function(e, t, r) {
        arguments[4][18][0].apply(r, arguments)
    }
        , {
            "./assert.cjs": 34,
            "./bytes.cjs": 36,
            "@metamask/superstruct": 179,
            "@noble/hashes/sha3": 189,
            dup: 18
        }],
    44: [function(e, t, r) {
        arguments[4][19][0].apply(r, arguments)
    }
        , {
            "./assert.cjs": 34,
            "./base64.cjs": 35,
            "./bytes.cjs": 36,
            "./caip-types.cjs": 37,
            "./checksum.cjs": 38,
            "./coercers.cjs": 39,
            "./collections.cjs": 40,
            "./encryption-types.cjs": 41,
            "./errors.cjs": 42,
            "./hex.cjs": 43,
            "./json.cjs": 45,
            "./keyring.cjs": 46,
            "./logging.cjs": 47,
            "./misc.cjs": 48,
            "./number.cjs": 49,
            "./opaque.cjs": 50,
            "./promise.cjs": 51,
            "./superstruct.cjs": 52,
            "./time.cjs": 53,
            "./transaction-types.cjs": 54,
            "./versions.cjs": 55,
            dup: 19
        }],
    45: [function(e, t, r) {
        arguments[4][20][0].apply(r, arguments)
    }
        , {
            "./assert.cjs": 34,
            "./misc.cjs": 48,
            "@metamask/superstruct": 179,
            dup: 20
        }],
    46: [function(e, t, r) {
        arguments[4][21][0].apply(r, arguments)
    }
        , {
            dup: 21
        }],
    47: [function(e, t, r) {
        arguments[4][22][0].apply(r, arguments)
    }
        , {
            debug: 197,
            dup: 22
        }],
    48: [function(e, t, r) {
        arguments[4][23][0].apply(r, arguments)
    }
        , {
            dup: 23
        }],
    49: [function(e, t, r) {
        arguments[4][24][0].apply(r, arguments)
    }
        , {
            "./assert.cjs": 34,
            "./hex.cjs": 43,
            dup: 24
        }],
    50: [function(e, t, r) {
        arguments[4][25][0].apply(r, arguments)
    }
        , {
            dup: 25
        }],
    51: [function(e, t, r) {
        arguments[4][26][0].apply(r, arguments)
    }
        , {
            dup: 26
        }],
    52: [function(e, t, r) {
        arguments[4][27][0].apply(r, arguments)
    }
        , {
            "@metamask/superstruct": 179,
            dup: 27
        }],
    53: [function(e, t, r) {
        arguments[4][28][0].apply(r, arguments)
    }
        , {
            dup: 28
        }],
    54: [function(e, t, r) {
        arguments[4][29][0].apply(r, arguments)
    }
        , {
            dup: 29
        }],
    55: [function(e, t, r) {
        arguments[4][30][0].apply(r, arguments)
    }
        , {
            "./assert.cjs": 34,
            "@metamask/superstruct": 179,
            dup: 30,
            semver: 255
        }],
    56: [function(e, t, r) {
        "use strict";
        var n = this && this.__importDefault || function(e) {
                return e && e.__esModule ? e : {
                    default: e
                }
            }
        ;
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.ObjectMultiplex = void 0;
        const s = e("readable-stream")
            , o = n(e("once"))
            , i = e("./Substream")
            , a = Symbol("IGNORE_SUBSTREAM");
        class c extends s.Duplex {
            constructor(e={}) {
                super(Object.assign({
                    objectMode: !0
                }, e)),
                    this._substreams = {}
            }
            createStream(e, t={}) {
                if (this.destroyed)
                    throw new Error(`ObjectMultiplex - parent stream for name "${e}" already destroyed`);
                if (this._readableState.ended || this._writableState.ended)
                    throw new Error(`ObjectMultiplex - parent stream for name "${e}" already ended`);
                if (!e)
                    throw new Error("ObjectMultiplex - name must not be empty");
                if (this._substreams[e])
                    throw new Error(`ObjectMultiplex - Substream for name "${e}" already exists`);
                const r = new i.Substream(Object.assign({
                    name: e,
                    parent: this
                }, t));
                return this._substreams[e] = r,
                    function(e, t) {
                        const r = (0,
                            o.default)(t);
                        (0,
                            s.finished)(e, {
                            readable: !1
                        }, r),
                            (0,
                                s.finished)(e, {
                                writable: !1
                            }, r)
                    }(this, (e => r.destroy(e || void 0))),
                    r
            }
            ignoreStream(e) {
                if (!e)
                    throw new Error("ObjectMultiplex - name must not be empty");
                if (this._substreams[e])
                    throw new Error(`ObjectMultiplex - Substream for name "${e}" already exists`);
                this._substreams[e] = a
            }
            _read() {}
            _write(e, t, r) {
                const {name: n, data: s} = e;
                if (!n)
                    return console.warn(`ObjectMultiplex - malformed chunk without name "${e}"`),
                        r();
                const o = this._substreams[n];
                return o ? (o !== a && o.push(s),
                    r()) : (console.warn(`ObjectMultiplex - orphaned data for stream "${n}"`),
                    r())
            }
        }
        r.ObjectMultiplex = c
    }
        , {
            "./Substream": 57,
            once: 207,
            "readable-stream": 226
        }],
    57: [function(e, t, r) {
        "use strict";
        var n = this && this.__rest || function(e, t) {
                var r = {};
                for (var n in e)
                    Object.prototype.hasOwnProperty.call(e, n) && t.indexOf(n) < 0 && (r[n] = e[n]);
                if (null != e && "function" == typeof Object.getOwnPropertySymbols) {
                    var s = 0;
                    for (n = Object.getOwnPropertySymbols(e); s < n.length; s++)
                        t.indexOf(n[s]) < 0 && Object.prototype.propertyIsEnumerable.call(e, n[s]) && (r[n[s]] = e[n[s]])
                }
                return r
            }
        ;
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.Substream = void 0;
        const s = e("readable-stream");
        class o extends s.Duplex {
            constructor(e) {
                var {parent: t, name: r} = e
                    , s = n(e, ["parent", "name"]);
                super(Object.assign({
                    objectMode: !0
                }, s)),
                    this._parent = t,
                    this._name = r
            }
            _read() {}
            _write(e, t, r) {
                this._parent.push({
                    name: this._name,
                    data: e
                }),
                    r()
            }
        }
        r.Substream = o
    }
        , {
            "readable-stream": 226
        }],
    58: [function(e, t, r) {
        "use strict";
        const n = e("./ObjectMultiplex");
        t.exports = n.ObjectMultiplex
    }
        , {
            "./ObjectMultiplex": 56
        }],
    59: [function(e, t, r) {
        "use strict";
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.BasePostMessageStream = void 0;
        const n = e("readable-stream")
            , s = () => {}
            , o = "SYN"
            , i = "ACK";
        class a extends n.Duplex {
            constructor(e) {
                super(Object.assign({
                    objectMode: !0
                }, e)),
                    this._init = !1,
                    this._haveSyn = !1,
                    this._log = () => null
            }
            _handshake() {
                this._write(o, null, s),
                    this.cork()
            }
            _onData(e) {
                if (this._init)
                    try {
                        this.push(e),
                            this._log(e, !1)
                    } catch (e) {
                        this.emit("error", e)
                    }
                else
                    e === o ? (this._haveSyn = !0,
                        this._write(i, null, s)) : e === i && (this._init = !0,
                    this._haveSyn || this._write(i, null, s),
                        this.uncork())
            }
            _read() {}
            _write(e, t, r) {
                e !== i && e !== o && this._log(e, !0),
                    this._postMessage(e),
                    r()
            }
            _setLogger(e) {
                this._log = e
            }
        }
        r.BasePostMessageStream = a
    }
        , {
            "readable-stream": 226
        }],
    60: [function(e, t, r) {
        "use strict";
        var n = this && this.__rest || function(e, t) {
                var r = {};
                for (var n in e)
                    Object.prototype.hasOwnProperty.call(e, n) && t.indexOf(n) < 0 && (r[n] = e[n]);
                if (null != e && "function" == typeof Object.getOwnPropertySymbols) {
                    var s = 0;
                    for (n = Object.getOwnPropertySymbols(e); s < n.length; s++)
                        t.indexOf(n[s]) < 0 && Object.prototype.propertyIsEnumerable.call(e, n[s]) && (r[n[s]] = e[n[s]])
                }
                return r
            }
        ;
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.WebWorkerParentPostMessageStream = void 0;
        const s = e("../BasePostMessageStream")
            , o = e("../utils");
        class i extends s.BasePostMessageStream {
            constructor(e) {
                var {worker: t} = e;
                super(n(e, ["worker"])),
                    this._target = o.DEDICATED_WORKER_NAME,
                    this._worker = t,
                    this._worker.onmessage = this._onMessage.bind(this),
                    this._handshake()
            }
            _postMessage(e) {
                this._worker.postMessage({
                    target: this._target,
                    data: e
                })
            }
            _onMessage(e) {
                const t = e.data;
                (0,
                    o.isValidStreamMessage)(t) && this._onData(t.data)
            }
            _destroy() {
                this._worker.onmessage = null,
                    this._worker = null
            }
        }
        r.WebWorkerParentPostMessageStream = i
    }
        , {
            "../BasePostMessageStream": 59,
            "../utils": 64
        }],
    61: [function(e, t, r) {
        "use strict";
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.WebWorkerPostMessageStream = void 0;
        const n = e("../BasePostMessageStream")
            , s = e("../utils");
        class o extends n.BasePostMessageStream {
            constructor(e={}) {
                if ("undefined" == typeof self || "undefined" == typeof WorkerGlobalScope)
                    throw new Error("WorkerGlobalScope not found. This class should only be instantiated in a WebWorker.");
                super(e),
                    this._name = s.DEDICATED_WORKER_NAME,
                    self.addEventListener("message", this._onMessage.bind(this)),
                    this._handshake()
            }
            _postMessage(e) {
                self.postMessage({
                    data: e
                })
            }
            _onMessage(e) {
                const t = e.data;
                (0,
                    s.isValidStreamMessage)(t) && t.target === this._name && this._onData(t.data)
            }
            _destroy() {}
        }
        r.WebWorkerPostMessageStream = o
    }
        , {
            "../BasePostMessageStream": 59,
            "../utils": 64
        }],
    62: [function(e, t, r) {
        "use strict";
        var n = this && this.__createBinding || (Object.create ? function(e, t, r, n) {
                        void 0 === n && (n = r);
                        var s = Object.getOwnPropertyDescriptor(t, r);
                        s && !("get"in s ? !t.__esModule : s.writable || s.configurable) || (s = {
                            enumerable: !0,
                            get: function() {
                                return t[r]
                            }
                        }),
                            Object.defineProperty(e, n, s)
                    }
                    : function(e, t, r, n) {
                        void 0 === n && (n = r),
                            e[n] = t[r]
                    }
            )
            , s = this && this.__exportStar || function(e, t) {
                for (var r in e)
                    "default" === r || Object.prototype.hasOwnProperty.call(t, r) || n(t, e, r)
            }
        ;
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            s(e("./window/WindowPostMessageStream"), r),
            s(e("./WebWorker/WebWorkerPostMessageStream"), r),
            s(e("./WebWorker/WebWorkerParentPostMessageStream"), r),
            s(e("./runtime/BrowserRuntimePostMessageStream"), r),
            s(e("./BasePostMessageStream"), r)
    }
        , {
            "./BasePostMessageStream": 59,
            "./WebWorker/WebWorkerParentPostMessageStream": 60,
            "./WebWorker/WebWorkerPostMessageStream": 61,
            "./runtime/BrowserRuntimePostMessageStream": 63,
            "./window/WindowPostMessageStream": 65
        }],
    63: [function(e, t, r) {
        "use strict";
        var n, s, o = this && this.__classPrivateFieldSet || function(e, t, r, n, s) {
                if ("m" === n)
                    throw new TypeError("Private method is not writable");
                if ("a" === n && !s)
                    throw new TypeError("Private accessor was defined without a setter");
                if ("function" == typeof t ? e !== t || !s : !t.has(e))
                    throw new TypeError("Cannot write private member to an object whose class did not declare it");
                return "a" === n ? s.call(e, r) : s ? s.value = r : t.set(e, r),
                    r
            }
            , i = this && this.__classPrivateFieldGet || function(e, t, r, n) {
                if ("a" === r && !n)
                    throw new TypeError("Private accessor was defined without a getter");
                if ("function" == typeof t ? e !== t || !n : !t.has(e))
                    throw new TypeError("Cannot read private member from an object whose class did not declare it");
                return "m" === r ? n : "a" === r ? n.call(e) : n ? n.value : t.get(e)
            }
            , a = this && this.__rest || function(e, t) {
                var r = {};
                for (var n in e)
                    Object.prototype.hasOwnProperty.call(e, n) && t.indexOf(n) < 0 && (r[n] = e[n]);
                if (null != e && "function" == typeof Object.getOwnPropertySymbols) {
                    var s = 0;
                    for (n = Object.getOwnPropertySymbols(e); s < n.length; s++)
                        t.indexOf(n[s]) < 0 && Object.prototype.propertyIsEnumerable.call(e, n[s]) && (r[n[s]] = e[n[s]])
                }
                return r
            }
        ;
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.BrowserRuntimePostMessageStream = void 0;
        const c = e("../BasePostMessageStream")
            , u = e("../utils");
        class l extends c.BasePostMessageStream {
            constructor(e) {
                var {name: t, target: r} = e;
                super(a(e, ["name", "target"])),
                    n.set(this, void 0),
                    s.set(this, void 0),
                    o(this, n, t, "f"),
                    o(this, s, r, "f"),
                    this._onMessage = this._onMessage.bind(this),
                    this._getRuntime().onMessage.addListener(this._onMessage),
                    this._handshake()
            }
            _postMessage(e) {
                this._getRuntime().sendMessage({
                    target: i(this, s, "f"),
                    data: e
                })
            }
            _onMessage(e) {
                (0,
                    u.isValidStreamMessage)(e) && e.target === i(this, n, "f") && this._onData(e.data)
            }
            _getRuntime() {
                var e, t;
                if ("chrome"in globalThis && "function" == typeof (null === (e = null === chrome || void 0 === chrome ? void 0 : chrome.runtime) || void 0 === e ? void 0 : e.sendMessage))
                    return chrome.runtime;
                if ("browser"in globalThis && "function" == typeof (null === (t = null === browser || void 0 === browser ? void 0 : browser.runtime) || void 0 === t ? void 0 : t.sendMessage))
                    return browser.runtime;
                throw new Error("browser.runtime.sendMessage is not a function. This class should only be instantiated in a web extension.")
            }
            _destroy() {
                this._getRuntime().onMessage.removeListener(this._onMessage)
            }
        }
        r.BrowserRuntimePostMessageStream = l,
            n = new WeakMap,
            s = new WeakMap
    }
        , {
            "../BasePostMessageStream": 59,
            "../utils": 64
        }],
    64: [function(e, t, r) {
        "use strict";
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.isValidStreamMessage = r.DEDICATED_WORKER_NAME = void 0;
        const n = e("@metamask/utils");
        r.DEDICATED_WORKER_NAME = "dedicatedWorker",
            r.isValidStreamMessage = function(e) {
                return (0,
                    n.isObject)(e) && Boolean(e.data) && ("number" == typeof e.data || "object" == typeof e.data || "string" == typeof e.data)
            }
    }
        , {
            "@metamask/utils": 76
        }],
    65: [function(e, t, r) {
        "use strict";
        var n, s, o = this && this.__rest || function(e, t) {
                var r = {};
                for (var n in e)
                    Object.prototype.hasOwnProperty.call(e, n) && t.indexOf(n) < 0 && (r[n] = e[n]);
                if (null != e && "function" == typeof Object.getOwnPropertySymbols) {
                    var s = 0;
                    for (n = Object.getOwnPropertySymbols(e); s < n.length; s++)
                        t.indexOf(n[s]) < 0 && Object.prototype.propertyIsEnumerable.call(e, n[s]) && (r[n[s]] = e[n[s]])
                }
                return r
            }
        ;
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.WindowPostMessageStream = void 0;
        const i = e("@metamask/utils")
            , a = e("../BasePostMessageStream")
            , c = e("../utils")
            , u = null === (n = Object.getOwnPropertyDescriptor(MessageEvent.prototype, "source")) || void 0 === n ? void 0 : n.get;
        (0,
            i.assert)(u, "MessageEvent.prototype.source getter is not defined.");
        const l = null === (s = Object.getOwnPropertyDescriptor(MessageEvent.prototype, "origin")) || void 0 === s ? void 0 : s.get;
        (0,
            i.assert)(l, "MessageEvent.prototype.origin getter is not defined.");
        class d extends a.BasePostMessageStream {
            constructor(e) {
                var {name: t, target: r, targetOrigin: n=location.origin, targetWindow: s=window} = e;
                if (super(o(e, ["name", "target", "targetOrigin", "targetWindow"])),
                "undefined" == typeof window || "function" != typeof window.postMessage)
                    throw new Error("window.postMessage is not a function. This class should only be instantiated in a Window.");
                this._name = t,
                    this._target = r,
                    this._targetOrigin = n,
                    this._targetWindow = s,
                    this._onMessage = this._onMessage.bind(this),
                    window.addEventListener("message", this._onMessage, !1),
                    this._handshake()
            }
            _postMessage(e) {
                this._targetWindow.postMessage({
                    target: this._target,
                    data: e
                }, this._targetOrigin)
            }
            _onMessage(e) {
                const t = e.data;
                "*" !== this._targetOrigin && l.call(e) !== this._targetOrigin || u.call(e) !== this._targetWindow || !(0,
                    c.isValidStreamMessage)(t) || t.target !== this._name || this._onData(t.data)
            }
            _destroy() {
                window.removeEventListener("message", this._onMessage, !1)
            }
        }
        r.WindowPostMessageStream = d
    }
        , {
            "../BasePostMessageStream": 59,
            "../utils": 64,
            "@metamask/utils": 76
        }],
    66: [function(e, t, r) {
        arguments[4][9][0].apply(r, arguments)
    }
        , {
            "./errors.cjs": 74,
            "@metamask/superstruct": 179,
            dup: 9
        }],
    67: [function(e, t, r) {
        arguments[4][10][0].apply(r, arguments)
    }
        , {
            "./assert.cjs": 66,
            "@metamask/superstruct": 179,
            dup: 10
        }],
    68: [function(e, t, r) {
        (function(t) {
                (function() {
                        "use strict";
                        Object.defineProperty(r, "__esModule", {
                            value: !0
                        }),
                            r.createDataView = r.concatBytes = r.valueToBytes = r.base64ToBytes = r.stringToBytes = r.numberToBytes = r.signedBigIntToBytes = r.bigIntToBytes = r.hexToBytes = r.bytesToBase64 = r.bytesToString = r.bytesToNumber = r.bytesToSignedBigInt = r.bytesToBigInt = r.bytesToHex = r.assertIsBytes = r.isBytes = void 0;
                        const n = e("@scure/base")
                            , s = e("./assert.cjs")
                            , o = e("./hex.cjs")
                            , i = 48
                            , a = 58
                            , c = 87;
                        const u = function() {
                            const e = [];
                            return () => {
                                if (0 === e.length)
                                    for (let t = 0; t < 256; t++)
                                        e.push(t.toString(16).padStart(2, "0"));
                                return e
                            }
                        }();
                        function l(e) {
                            return e instanceof Uint8Array
                        }
                        function d(e) {
                            (0,
                                s.assert)(l(e), "Value must be a Uint8Array.")
                        }
                        function f(e) {
                            if (d(e),
                            0 === e.length)
                                return "0x";
                            const t = u()
                                , r = new Array(e.length);
                            for (let n = 0; n < e.length; n++)
                                r[n] = t[e[n]];
                            return (0,
                                o.add0x)(r.join(""))
                        }
                        function p(e) {
                            d(e);
                            const t = f(e);
                            return BigInt(t)
                        }
                        function h(e) {
                            if ("0x" === e?.toLowerCase?.())
                                return new Uint8Array;
                            (0,
                                o.assertIsHexString)(e);
                            const t = (0,
                                o.remove0x)(e).toLowerCase()
                                , r = t.length % 2 == 0 ? t : `0${t}`
                                , n = new Uint8Array(r.length / 2);
                            for (let e = 0; e < n.length; e++) {
                                const t = r.charCodeAt(2 * e)
                                    , s = r.charCodeAt(2 * e + 1)
                                    , o = t - (t < a ? i : c)
                                    , u = s - (s < a ? i : c);
                                n[e] = 16 * o + u
                            }
                            return n
                        }
                        function g(e) {
                            (0,
                                s.assert)("bigint" == typeof e, "Value must be a bigint."),
                                (0,
                                    s.assert)(e >= BigInt(0), "Value must be a non-negative bigint.");
                            return h(e.toString(16))
                        }
                        function m(e) {
                            (0,
                                s.assert)("number" == typeof e, "Value must be a number."),
                                (0,
                                    s.assert)(e >= 0, "Value must be a non-negative number."),
                                (0,
                                    s.assert)(Number.isSafeInteger(e), "Value is not a safe integer. Use `bigIntToBytes` instead.");
                            return h(e.toString(16))
                        }
                        function b(e) {
                            return (0,
                                s.assert)("string" == typeof e, "Value must be a string."),
                                (new TextEncoder).encode(e)
                        }
                        function y(e) {
                            if ("bigint" == typeof e)
                                return g(e);
                            if ("number" == typeof e)
                                return m(e);
                            if ("string" == typeof e)
                                return e.startsWith("0x") ? h(e) : b(e);
                            if (l(e))
                                return e;
                            throw new TypeError(`Unsupported value type: "${typeof e}".`)
                        }
                        r.isBytes = l,
                            r.assertIsBytes = d,
                            r.bytesToHex = f,
                            r.bytesToBigInt = p,
                            r.bytesToSignedBigInt = function(e) {
                                d(e);
                                let t = BigInt(0);
                                for (const r of e)
                                    t = (t << BigInt(8)) + BigInt(r);
                                return BigInt.asIntN(8 * e.length, t)
                            }
                            ,
                            r.bytesToNumber = function(e) {
                                d(e);
                                const t = p(e);
                                return (0,
                                    s.assert)(t <= BigInt(Number.MAX_SAFE_INTEGER), "Number is not a safe integer. Use `bytesToBigInt` instead."),
                                    Number(t)
                            }
                            ,
                            r.bytesToString = function(e) {
                                return d(e),
                                    (new TextDecoder).decode(e)
                            }
                            ,
                            r.bytesToBase64 = function(e) {
                                return d(e),
                                    n.base64.encode(e)
                            }
                            ,
                            r.hexToBytes = h,
                            r.bigIntToBytes = g,
                            r.signedBigIntToBytes = function(e, t) {
                                (0,
                                    s.assert)("bigint" == typeof e, "Value must be a bigint."),
                                    (0,
                                        s.assert)("number" == typeof t, "Byte length must be a number."),
                                    (0,
                                        s.assert)(t > 0, "Byte length must be greater than 0."),
                                    (0,
                                        s.assert)(function(e, t) {
                                        (0,
                                            s.assert)(t > 0);
                                        const r = e >> BigInt(31);
                                        return !((~e & r) + (e & ~r) >> BigInt(8 * t - 1))
                                    }(e, t), "Byte length is too small to represent the given value.");
                                let r = e;
                                const n = new Uint8Array(t);
                                for (let e = 0; e < n.length; e++)
                                    n[e] = Number(BigInt.asUintN(8, r)),
                                        r >>= BigInt(8);
                                return n.reverse()
                            }
                            ,
                            r.numberToBytes = m,
                            r.stringToBytes = b,
                            r.base64ToBytes = function(e) {
                                return (0,
                                    s.assert)("string" == typeof e, "Value must be a string."),
                                    n.base64.decode(e)
                            }
                            ,
                            r.valueToBytes = y,
                            r.concatBytes = function(e) {
                                const t = new Array(e.length);
                                let r = 0;
                                for (let n = 0; n < e.length; n++) {
                                    const s = y(e[n]);
                                    t[n] = s,
                                        r += s.length
                                }
                                const n = new Uint8Array(r);
                                for (let e = 0, r = 0; e < t.length; e++)
                                    n.set(t[e], r),
                                        r += t[e].length;
                                return n
                            }
                            ,
                            r.createDataView = function(e) {
                                if (void 0 !== t && e instanceof t) {
                                    const t = e.buffer.slice(e.byteOffset, e.byteOffset + e.byteLength);
                                    return new DataView(t)
                                }
                                return new DataView(e.buffer,e.byteOffset,e.byteLength)
                            }
                    }
                ).call(this)
            }
        ).call(this, e("buffer").Buffer)
    }
        , {
            "./assert.cjs": 66,
            "./hex.cjs": 75,
            "@scure/base": 191,
            buffer: 195
        }],
    69: [function(e, t, r) {
        arguments[4][12][0].apply(r, arguments)
    }
        , {
            "./superstruct.cjs": 84,
            "@metamask/superstruct": 179,
            dup: 12
        }],
    70: [function(e, t, r) {
        arguments[4][13][0].apply(r, arguments)
    }
        , {
            "./base64.cjs": 67,
            "@metamask/superstruct": 179,
            dup: 13
        }],
    71: [function(e, t, r) {
        arguments[4][14][0].apply(r, arguments)
    }
        , {
            "./assert.cjs": 66,
            "./bytes.cjs": 68,
            "./hex.cjs": 75,
            "@metamask/superstruct": 179,
            dup: 14
        }],
    72: [function(e, t, r) {
        arguments[4][15][0].apply(r, arguments)
    }
        , {
            dup: 15
        }],
    73: [function(e, t, r) {
        arguments[4][16][0].apply(r, arguments)
    }
        , {
            dup: 16
        }],
    74: [function(e, t, r) {
        arguments[4][17][0].apply(r, arguments)
    }
        , {
            "./misc.cjs": 80,
            dup: 17,
            "pony-cause": 208
        }],
    75: [function(e, t, r) {
        arguments[4][18][0].apply(r, arguments)
    }
        , {
            "./assert.cjs": 66,
            "./bytes.cjs": 68,
            "@metamask/superstruct": 179,
            "@noble/hashes/sha3": 189,
            dup: 18
        }],
    76: [function(e, t, r) {
        arguments[4][19][0].apply(r, arguments)
    }
        , {
            "./assert.cjs": 66,
            "./base64.cjs": 67,
            "./bytes.cjs": 68,
            "./caip-types.cjs": 69,
            "./checksum.cjs": 70,
            "./coercers.cjs": 71,
            "./collections.cjs": 72,
            "./encryption-types.cjs": 73,
            "./errors.cjs": 74,
            "./hex.cjs": 75,
            "./json.cjs": 77,
            "./keyring.cjs": 78,
            "./logging.cjs": 79,
            "./misc.cjs": 80,
            "./number.cjs": 81,
            "./opaque.cjs": 82,
            "./promise.cjs": 83,
            "./superstruct.cjs": 84,
            "./time.cjs": 85,
            "./transaction-types.cjs": 86,
            "./versions.cjs": 87,
            dup: 19
        }],
    77: [function(e, t, r) {
        arguments[4][20][0].apply(r, arguments)
    }
        , {
            "./assert.cjs": 66,
            "./misc.cjs": 80,
            "@metamask/superstruct": 179,
            dup: 20
        }],
    78: [function(e, t, r) {
        arguments[4][21][0].apply(r, arguments)
    }
        , {
            dup: 21
        }],
    79: [function(e, t, r) {
        arguments[4][22][0].apply(r, arguments)
    }
        , {
            debug: 197,
            dup: 22
        }],
    80: [function(e, t, r) {
        arguments[4][23][0].apply(r, arguments)
    }
        , {
            dup: 23
        }],
    81: [function(e, t, r) {
        arguments[4][24][0].apply(r, arguments)
    }
        , {
            "./assert.cjs": 66,
            "./hex.cjs": 75,
            dup: 24
        }],
    82: [function(e, t, r) {
        arguments[4][25][0].apply(r, arguments)
    }
        , {
            dup: 25
        }],
    83: [function(e, t, r) {
        arguments[4][26][0].apply(r, arguments)
    }
        , {
            dup: 26
        }],
    84: [function(e, t, r) {
        arguments[4][27][0].apply(r, arguments)
    }
        , {
            "@metamask/superstruct": 179,
            dup: 27
        }],
    85: [function(e, t, r) {
        arguments[4][28][0].apply(r, arguments)
    }
        , {
            dup: 28
        }],
    86: [function(e, t, r) {
        arguments[4][29][0].apply(r, arguments)
    }
        , {
            dup: 29
        }],
    87: [function(e, t, r) {
        arguments[4][30][0].apply(r, arguments)
    }
        , {
            "./assert.cjs": 66,
            "@metamask/superstruct": 179,
            dup: 30,
            semver: 255
        }],
    88: [function(e, t, r) {
        "use strict";
        var n, s, o = this && this.__classPrivateFieldSet || function(e, t, r, n, s) {
                if ("m" === n)
                    throw new TypeError("Private method is not writable");
                if ("a" === n && !s)
                    throw new TypeError("Private accessor was defined without a setter");
                if ("function" == typeof t ? e !== t || !s : !t.has(e))
                    throw new TypeError("Cannot write private member to an object whose class did not declare it");
                return "a" === n ? s.call(e, r) : s ? s.value = r : t.set(e, r),
                    r
            }
            , i = this && this.__classPrivateFieldGet || function(e, t, r, n) {
                if ("a" === r && !n)
                    throw new TypeError("Private accessor was defined without a getter");
                if ("function" == typeof t ? e !== t || !n : !t.has(e))
                    throw new TypeError("Cannot read private member from an object whose class did not declare it");
                return "m" === r ? n : "a" === r ? n.call(e) : n ? n.value : t.get(e)
            }
            , a = this && this.__importDefault || function(e) {
                return e && e.__esModule ? e : {
                    default: e
                }
            }
        ;
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.BaseProvider = void 0;
        const c = e("@metamask/json-rpc-engine")
            , u = e("@metamask/rpc-errors")
            , l = a(e("@metamask/safe-event-emitter"))
            , d = a(e("fast-deep-equal"))
            , f = a(e("./messages.cjs"))
            , p = e("./utils.cjs");
        class h extends l.default {
            constructor({logger: e=console, maxEventListeners: t=100, rpcMiddleware: r=[]}={}) {
                super(),
                    n.set(this, void 0),
                    s.set(this, void 0),
                    this._log = e,
                    this.setMaxListeners(t),
                    this._state = {
                        ...h._defaultState
                    },
                    o(this, s, null, "f"),
                    o(this, n, null, "f"),
                    this._handleAccountsChanged = this._handleAccountsChanged.bind(this),
                    this._handleConnect = this._handleConnect.bind(this),
                    this._handleChainChanged = this._handleChainChanged.bind(this),
                    this._handleDisconnect = this._handleDisconnect.bind(this),
                    this._handleUnlockStateChanged = this._handleUnlockStateChanged.bind(this),
                    this._rpcRequest = this._rpcRequest.bind(this),
                    this.request = this.request.bind(this);
                const i = new c.JsonRpcEngine;
                r.forEach((e => i.push(e))),
                    this._rpcEngine = i
            }
            get chainId() {
                return i(this, n, "f")
            }
            get selectedAddress() {
                return i(this, s, "f")
            }
            isConnected() {
                return this._state.isConnected
            }
            async request(e) {
                if (!e || "object" != typeof e || Array.isArray(e))
                    throw u.rpcErrors.invalidRequest({
                        message: f.default.errors.invalidRequestArgs(),
                        data: e
                    });
                const {method: t, params: r} = e;
                if ("string" != typeof t || 0 === t.length)
                    throw u.rpcErrors.invalidRequest({
                        message: f.default.errors.invalidRequestMethod(),
                        data: e
                    });
                if (void 0 !== r && !Array.isArray(r) && ("object" != typeof r || null === r))
                    throw u.rpcErrors.invalidRequest({
                        message: f.default.errors.invalidRequestParams(),
                        data: e
                    });
                const n = null == r ? {
                    method: t
                } : {
                    method: t,
                    params: r
                };
                return new Promise(( (e, t) => {
                        this._rpcRequest(n, (0,
                            p.getRpcPromiseCallback)(e, t))
                    }
                ))
            }
            _initializeState(e) {
                if (this._state.initialized)
                    throw new Error("Provider already initialized.");
                if (e) {
                    const {accounts: t, chainId: r, isUnlocked: n, networkVersion: s, isConnected: o} = e;
                    this._handleConnect({
                        chainId: r,
                        isConnected: o
                    }),
                        this._handleChainChanged({
                            chainId: r,
                            networkVersion: s,
                            isConnected: o
                        }),
                        this._handleUnlockStateChanged({
                            accounts: t,
                            isUnlocked: n
                        }),
                        this._handleAccountsChanged(t)
                }
                this._state.initialized = !0,
                    this.emit("_initialized")
            }
            _rpcRequest(e, t) {
                let r = t;
                return Array.isArray(e) || (e.jsonrpc || (e.jsonrpc = "2.0"),
                "eth_accounts" !== e.method && "eth_requestAccounts" !== e.method || (r = (r, n) => {
                        this._handleAccountsChanged(n.result ?? [], "eth_accounts" === e.method),
                            t(r, n)
                    }
                )),
                    this._rpcEngine.handle(e, r)
            }
            _handleConnect({chainId: e, isConnected: t}) {
                !this._state.isConnected && t && (this._state.isConnected = !0,
                    this.emit("connect", {
                        chainId: e
                    }),
                    this._log.debug(f.default.info.connected(e)))
            }
            _handleDisconnect(e, t) {
                if (this._state.isConnected || !this._state.isPermanentlyDisconnected && !e) {
                    let r;
                    this._state.isConnected = !1,
                        e ? (r = new u.JsonRpcError(1013,t ?? f.default.errors.disconnected()),
                            this._log.debug(r)) : (r = new u.JsonRpcError(1011,t ?? f.default.errors.permanentlyDisconnected()),
                            this._log.error(r),
                            o(this, n, null, "f"),
                            this._state.accounts = null,
                            o(this, s, null, "f"),
                            this._state.isUnlocked = !1,
                            this._state.isPermanentlyDisconnected = !0),
                        this.emit("disconnect", r)
                }
            }
            _handleChainChanged({chainId: e, isConnected: t}={}) {
                (0,
                    p.isValidChainId)(e) ? (this._handleConnect({
                    chainId: e,
                    isConnected: t
                }),
                e !== i(this, n, "f") && (o(this, n, e, "f"),
                this._state.initialized && this.emit("chainChanged", i(this, n, "f")))) : this._log.error(f.default.errors.invalidNetworkParams(), {
                    chainId: e
                })
            }
            _handleAccountsChanged(e, t=!1) {
                let r = e;
                Array.isArray(e) || (this._log.error("MetaMask: Received invalid accounts parameter. Please report this bug.", e),
                    r = []);
                for (const t of e)
                    if ("string" != typeof t) {
                        this._log.error("MetaMask: Received non-string account. Please report this bug.", e),
                            r = [];
                        break
                    }
                if (!(0,
                    d.default)(this._state.accounts, r) && (t && null !== this._state.accounts && this._log.error("MetaMask: 'eth_accounts' unexpectedly updated accounts. Please report this bug.", r),
                    this._state.accounts = r,
                i(this, s, "f") !== r[0] && o(this, s, r[0] || null, "f"),
                    this._state.initialized)) {
                    const e = [...r];
                    this.emit("accountsChanged", e)
                }
            }
            _handleUnlockStateChanged({accounts: e, isUnlocked: t}={}) {
                "boolean" == typeof t ? t !== this._state.isUnlocked && (this._state.isUnlocked = t,
                    this._handleAccountsChanged(e ?? [])) : this._log.error("MetaMask: Received invalid isUnlocked parameter. Please report this bug.")
            }
        }
        r.BaseProvider = h,
            n = new WeakMap,
            s = new WeakMap,
            h._defaultState = {
                accounts: null,
                isConnected: !1,
                isUnlocked: !1,
                initialized: !1,
                isPermanentlyDisconnected: !1
            }
    }
        , {
            "./messages.cjs": 97,
            "./utils.cjs": 101,
            "@metamask/json-rpc-engine": 7,
            "@metamask/rpc-errors": 153,
            "@metamask/safe-event-emitter": 177,
            "fast-deep-equal": 201
        }],
    89: [function(e, t, r) {
        "use strict";
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.CAIP294EventNames = void 0,
            r.announceWallet = function(e) {
                i(e) || a(`Invalid CAIP-294 WalletData object received from ${o.Prompt}.`);
                const t = () => window.dispatchEvent(new CustomEvent(o.Announce,{
                    detail: {
                        id: 1,
                        jsonrpc: "2.0",
                        method: "wallet_announce",
                        params: e
                    }
                }));
                t(),
                    window.addEventListener(o.Prompt, (e => {
                            (function(e) {
                                    return e instanceof CustomEvent && e.type === o.Prompt && (0,
                                        n.isObject)(e.detail) && "wallet_prompt" === e.detail.method && function(e) {
                                        const t = void 0 === e.chains || Array.isArray(e.chains) && e.chains.every((e => "string" == typeof e))
                                            , r = void 0 === e.authName || "string" == typeof e.authName;
                                        return t && r
                                    }(e.detail.params)
                                }
                            )(e) || a(`Invalid CAIP-294 RequestWalletEvent object received from ${o.Prompt}.`),
                                t()
                        }
                    ))
            }
            ,
            r.requestWallet = function(e) {
                window.addEventListener(o.Announce, (t => {
                        (function(e) {
                                return e instanceof CustomEvent && e.type === o.Announce && (0,
                                    n.isObject)(e.detail) && "wallet_announce" === e.detail.method && i(e.detail.params)
                            }
                        )(t) || a(`Invalid CAIP-294 WalletData object received from ${o.Announce}.`),
                            e(t.detail)
                    }
                )),
                    window.dispatchEvent(new CustomEvent(o.Prompt,{
                        detail: {
                            id: 1,
                            jsonrpc: "2.0",
                            method: "wallet_prompt",
                            params: {}
                        }
                    }))
            }
        ;
        const n = e("@metamask/utils")
            , s = e("./utils.cjs");
        var o;
        function i(e) {
            return (0,
                n.isObject)(e) && "string" == typeof e.uuid && s.UUID_V4_REGEX.test(e.uuid) && "string" == typeof e.name && Boolean(e.name) && "string" == typeof e.icon && e.icon.startsWith("data:image") && "string" == typeof e.rdns && s.FQDN_REGEX.test(e.rdns) && (void 0 === e.extensionId || "string" == typeof e.extensionId && e.extensionId.length > 0)
        }
        function a(e) {
            throw new Error(`${e} See https://github.com/ChainAgnostic/CAIPs/blob/bc4942857a8e04593ed92f7dc66653577a1c4435/CAIPs/caip-294.md for requirements.`)
        }
        !function(e) {
            e.Announce = "caip294:wallet_announce",
                e.Prompt = "caip294:wallet_prompt"
        }(o || (r.CAIP294EventNames = o = {}))
    }
        , {
            "./utils.cjs": 101,
            "@metamask/utils": 113
        }],
    90: [function(e, t, r) {
        "use strict";
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.requestProvider = function(e) {
                window.addEventListener(o.Announce, (t => {
                        (function(e) {
                                return e instanceof CustomEvent && e.type === o.Announce && Object.isFrozen(e.detail) && i(e.detail)
                            }
                        )(t) || a(`Invalid EIP-6963 AnnounceProviderEvent object received from ${o.Announce} event.`),
                            e(t.detail)
                    }
                )),
                    window.dispatchEvent(new Event(o.Request))
            }
            ,
            r.announceProvider = function(e) {
                i(e) || a("Invalid EIP-6963 ProviderDetail object.");
                const {info: t, provider: r} = e
                    , n = () => window.dispatchEvent(new CustomEvent(o.Announce,{
                    detail: Object.freeze({
                        info: {
                            ...t
                        },
                        provider: r
                    })
                }));
                n(),
                    window.addEventListener(o.Request, (e => {
                            (function(e) {
                                    return e instanceof Event && e.type === o.Request
                                }
                            )(e) || a(`Invalid EIP-6963 RequestProviderEvent object received from ${o.Request} event.`),
                                n()
                        }
                    ))
            }
        ;
        const n = e("@metamask/utils")
            , s = e("./utils.cjs");
        var o;
        function i(e) {
            if (!(0,
                n.isObject)(e) || !(0,
                n.isObject)(e.info) || !(0,
                n.isObject)(e.provider))
                return !1;
            const {info: t} = e;
            return "string" == typeof t.uuid && s.UUID_V4_REGEX.test(t.uuid) && "string" == typeof t.name && Boolean(t.name) && "string" == typeof t.icon && t.icon.startsWith("data:image") && "string" == typeof t.rdns && s.FQDN_REGEX.test(t.rdns)
        }
        function a(e) {
            throw new Error(`${e} See https://eips.ethereum.org/EIPS/eip-6963 for requirements.`)
        }
        !function(e) {
            e.Announce = "eip6963:announceProvider",
                e.Request = "eip6963:requestProvider"
        }(o || (o = {}))
    }
        , {
            "./utils.cjs": 101,
            "@metamask/utils": 113
        }],
    91: [function(e, t, r) {
        "use strict";
        var n, s = this && this.__classPrivateFieldSet || function(e, t, r, n, s) {
                if ("m" === n)
                    throw new TypeError("Private method is not writable");
                if ("a" === n && !s)
                    throw new TypeError("Private accessor was defined without a setter");
                if ("function" == typeof t ? e !== t || !s : !t.has(e))
                    throw new TypeError("Cannot write private member to an object whose class did not declare it");
                return "a" === n ? s.call(e, r) : s ? s.value = r : t.set(e, r),
                    r
            }
            , o = this && this.__classPrivateFieldGet || function(e, t, r, n) {
                if ("a" === r && !n)
                    throw new TypeError("Private accessor was defined without a getter");
                if ("function" == typeof t ? e !== t || !n : !t.has(e))
                    throw new TypeError("Cannot read private member from an object whose class did not declare it");
                return "m" === r ? n : "a" === r ? n.call(e) : n ? n.value : t.get(e)
            }
            , i = this && this.__importDefault || function(e) {
                return e && e.__esModule ? e : {
                    default: e
                }
            }
        ;
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.MetaMaskInpageProvider = r.MetaMaskInpageProviderStreamName = void 0;
        const a = e("@metamask/rpc-errors")
            , c = i(e("./messages.cjs"))
            , u = e("./siteMetadata.cjs")
            , l = e("./StreamProvider.cjs")
            , d = e("./utils.cjs");
        r.MetaMaskInpageProviderStreamName = "metamask-provider";
        class f extends l.AbstractStreamProvider {
            constructor(e, {logger: t=console, maxEventListeners: r=100, shouldSendMetadata: o}={}) {
                if (super(e, {
                    logger: t,
                    maxEventListeners: r,
                    rpcMiddleware: (0,
                        d.getDefaultExternalMiddleware)(t)
                }),
                    this._sentWarnings = {
                        enable: !1,
                        experimentalMethods: !1,
                        send: !1,
                        events: {
                            close: !1,
                            data: !1,
                            networkChanged: !1,
                            notification: !1
                        }
                    },
                    n.set(this, void 0),
                    this._initializeStateAsync(),
                    s(this, n, null, "f"),
                    this.isMetaMask = !0,
                    this._sendSync = this._sendSync.bind(this),
                    this.enable = this.enable.bind(this),
                    this.send = this.send.bind(this),
                    this.sendAsync = this.sendAsync.bind(this),
                    this._warnOfDeprecation = this._warnOfDeprecation.bind(this),
                    this._metamask = this._getExperimentalApi(),
                    this._jsonRpcConnection.events.on("notification", (e => {
                            const {method: t} = e;
                            d.EMITTED_NOTIFICATIONS.includes(t) && (this.emit("data", e),
                                this.emit("notification", e.params.result))
                        }
                    )),
                    o)
                    if ("complete" === document.readyState)
                        (0,
                            u.sendSiteMetadata)(this._rpcEngine, this._log);
                    else {
                        const e = () => {
                                (0,
                                    u.sendSiteMetadata)(this._rpcEngine, this._log),
                                    window.removeEventListener("DOMContentLoaded", e)
                            }
                        ;
                        window.addEventListener("DOMContentLoaded", e)
                    }
            }
            get chainId() {
                return super.chainId
            }
            get networkVersion() {
                return o(this, n, "f")
            }
            get selectedAddress() {
                return super.selectedAddress
            }
            sendAsync(e, t) {
                this._rpcRequest(e, t)
            }
            addListener(e, t) {
                return this._warnOfDeprecation(e),
                    super.addListener(e, t)
            }
            on(e, t) {
                return this._warnOfDeprecation(e),
                    super.on(e, t)
            }
            once(e, t) {
                return this._warnOfDeprecation(e),
                    super.once(e, t)
            }
            prependListener(e, t) {
                return this._warnOfDeprecation(e),
                    super.prependListener(e, t)
            }
            prependOnceListener(e, t) {
                return this._warnOfDeprecation(e),
                    super.prependOnceListener(e, t)
            }
            _handleDisconnect(e, t) {
                super._handleDisconnect(e, t),
                o(this, n, "f") && !e && s(this, n, null, "f")
            }
            _warnOfDeprecation(e) {
                !1 === this._sentWarnings?.events[e] && (this._log.warn(c.default.warnings.events[e]),
                    this._sentWarnings.events[e] = !0)
            }
            async enable() {
                return this._sentWarnings.enable || (this._log.warn(c.default.warnings.enableDeprecation),
                    this._sentWarnings.enable = !0),
                    new Promise(( (e, t) => {
                            try {
                                this._rpcRequest({
                                    method: "eth_requestAccounts",
                                    params: []
                                }, (0,
                                    d.getRpcPromiseCallback)(e, t))
                            } catch (e) {
                                t(e)
                            }
                        }
                    ))
            }
            send(e, t) {
                return this._sentWarnings.send || (this._log.warn(c.default.warnings.sendDeprecation),
                    this._sentWarnings.send = !0),
                    "string" != typeof e || t && !Array.isArray(t) ? e && "object" == typeof e && "function" == typeof t ? this._rpcRequest(e, t) : this._sendSync(e) : new Promise(( (r, n) => {
                            try {
                                this._rpcRequest({
                                    method: e,
                                    params: t
                                }, (0,
                                    d.getRpcPromiseCallback)(r, n, !1))
                            } catch (e) {
                                n(e)
                            }
                        }
                    ))
            }
            _sendSync(e) {
                let t;
                switch (e.method) {
                    case "eth_accounts":
                        t = this.selectedAddress ? [this.selectedAddress] : [];
                        break;
                    case "eth_coinbase":
                        t = this.selectedAddress ?? null;
                        break;
                    case "eth_uninstallFilter":
                        this._rpcRequest(e, d.NOOP),
                            t = !0;
                        break;
                    case "net_version":
                        t = o(this, n, "f") ?? null;
                        break;
                    default:
                        throw new Error(c.default.errors.unsupportedSync(e.method))
                }
                return {
                    id: e.id,
                    jsonrpc: e.jsonrpc,
                    result: t
                }
            }
            _getExperimentalApi() {
                return new Proxy({
                    isUnlocked: async () => (this._state.initialized || await new Promise((e => {
                            this.on("_initialized", ( () => e()))
                        }
                    )),
                        this._state.isUnlocked),
                    requestBatch: async e => {
                        if (!Array.isArray(e))
                            throw a.rpcErrors.invalidRequest({
                                message: "Batch requests must be made with an array of request objects.",
                                data: e
                            });
                        return new Promise(( (t, r) => {
                                this._rpcRequest(e, (0,
                                    d.getRpcPromiseCallback)(t, r))
                            }
                        ))
                    }
                },{
                    get: (e, t, ...r) => (this._sentWarnings.experimentalMethods || (this._log.warn(c.default.warnings.experimentalMethods),
                        this._sentWarnings.experimentalMethods = !0),
                        Reflect.get(e, t, ...r))
                })
            }
            _handleChainChanged({chainId: e, networkVersion: t, isConnected: r}={}) {
                super._handleChainChanged({
                    chainId: e,
                    networkVersion: t,
                    isConnected: r
                });
                const i = "loading" === t ? null : t;
                i !== o(this, n, "f") && (s(this, n, i, "f"),
                this._state.initialized && this.emit("networkChanged", o(this, n, "f")))
            }
        }
        r.MetaMaskInpageProvider = f,
            n = new WeakMap
    }
        , {
            "./StreamProvider.cjs": 92,
            "./messages.cjs": 97,
            "./siteMetadata.cjs": 100,
            "./utils.cjs": 101,
            "@metamask/rpc-errors": 153
        }],
    92: [function(e, t, r) {
        "use strict";
        var n = this && this.__importDefault || function(e) {
                return e && e.__esModule ? e : {
                    default: e
                }
            }
        ;
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.StreamProvider = r.AbstractStreamProvider = void 0;
        const s = e("@metamask/json-rpc-middleware-stream")
            , o = e("is-stream/index.js")
            , i = e("readable-stream")
            , a = e("./BaseProvider.cjs")
            , c = n(e("./messages.cjs"))
            , u = e("./utils.cjs");
        class l extends a.BaseProvider {
            constructor(e, {logger: t=console, maxEventListeners: r=100, rpcMiddleware: n=[]}={}) {
                if (super({
                    logger: t,
                    maxEventListeners: r,
                    rpcMiddleware: n
                }),
                    !(0,
                        o.duplex)(e))
                    throw new Error(c.default.errors.invalidDuplexStream());
                this._handleStreamDisconnect = this._handleStreamDisconnect.bind(this),
                    this._jsonRpcConnection = (0,
                        s.createStreamMiddleware)({
                        retryOnMessage: "METAMASK_EXTENSION_CONNECT_CAN_RETRY"
                    }),
                    (0,
                        i.pipeline)(e, this._jsonRpcConnection.stream, e, this._handleStreamDisconnect.bind(this, "MetaMask RpcProvider")),
                    this._rpcEngine.push(this._jsonRpcConnection.middleware),
                    this._jsonRpcConnection.events.on("notification", (t => {
                            const {method: r, params: n} = t;
                            "metamask_accountsChanged" === r ? this._handleAccountsChanged(n) : "metamask_unlockStateChanged" === r ? this._handleUnlockStateChanged(n) : "metamask_chainChanged" === r ? this._handleChainChanged(n) : u.EMITTED_NOTIFICATIONS.includes(r) ? this.emit("message", {
                                type: r,
                                data: n
                            }) : "METAMASK_STREAM_FAILURE" === r && e.destroy(new Error(c.default.errors.permanentlyDisconnected()))
                        }
                    ))
            }
            async _initializeStateAsync() {
                let e;
                try {
                    e = await this.request({
                        method: "metamask_getProviderState"
                    })
                } catch (e) {
                    this._log.error("MetaMask: Failed to get initial state. Please report this bug.", e)
                }
                this._initializeState(e)
            }
            _handleStreamDisconnect(e, t) {
                let r = `MetaMask: Lost connection to "${e}".`;
                t?.stack && (r += `\n${t.stack}`),
                    this._log.warn(r),
                this.listenerCount("error") > 0 && this.emit("error", r),
                    this._handleDisconnect(!1, t ? t.message : void 0)
            }
            _handleChainChanged({chainId: e, networkVersion: t, isConnected: r}={}) {
                (0,
                    u.isValidChainId)(e) && (0,
                    u.isValidNetworkVersion)(t) ? (super._handleChainChanged({
                    chainId: e,
                    isConnected: r
                }),
                r || this._handleDisconnect(!0)) : this._log.error(c.default.errors.invalidNetworkParams(), {
                    chainId: e,
                    networkVersion: t
                })
            }
        }
        r.AbstractStreamProvider = l;
        r.StreamProvider = class extends l {
            async initialize() {
                return this._initializeStateAsync()
            }
        }
    }
        , {
            "./BaseProvider.cjs": 88,
            "./messages.cjs": 97,
            "./utils.cjs": 101,
            "@metamask/json-rpc-middleware-stream": 33,
            "is-stream/index.js": 205,
            "readable-stream": 226
        }],
    93: [function(e, t, r) {
        "use strict";
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.ERC20 = r.ERC1155 = r.ERC721 = void 0,
            r.ERC721 = "ERC721",
            r.ERC1155 = "ERC1155",
            r.ERC20 = "ERC20"
    }
        , {}],
    94: [function(e, t, r) {
        "use strict";
        var n = this && this.__importDefault || function(e) {
                return e && e.__esModule ? e : {
                    default: e
                }
            }
        ;
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.createExternalExtensionProvider = function(e="stable") {
                let t;
                try {
                    const r = function(e) {
                        let t;
                        switch (f?.name) {
                            case "edge-chromium":
                                t = c.default.edgeChromiumIds;
                                break;
                            case "firefox":
                                t = c.default.firefoxIds;
                                break;
                            default:
                                t = c.default.chromeIds
                        }
                        return t[e] ?? e
                    }(e)
                        , n = chrome.runtime.connect(r)
                        , o = new i.PortDuplexStream(n)
                        , p = u.MetaMaskInpageProviderStreamName
                        , h = new s.default;
                    (0,
                        a.pipeline)(o, h, o, (e => {
                            let t = `Lost connection to "${p}".`;
                            e?.stack && (t += `\n${e.stack}`),
                                console.warn(t)
                        }
                    )),
                        t = new l.StreamProvider(h.createStream(p),{
                            logger: console,
                            rpcMiddleware: (0,
                                d.getDefaultExternalMiddleware)(console)
                        }),
                        t.initialize()
                } catch (e) {
                    throw console.dir("MetaMask connect error.", e),
                        e
                }
                return t
            }
            ,
            r.getBuildType = function(e) {
                return {
                    "io.metamask": "stable",
                    "io.metamask.beta": "beta",
                    "io.metamask.flask": "flask"
                }[e]
            }
        ;
        const s = n(e("@metamask/object-multiplex"))
            , o = e("detect-browser")
            , i = e("extension-port-stream")
            , a = e("readable-stream")
            , c = n(e("./external-extension-config.json"))
            , u = e("../MetaMaskInpageProvider.cjs")
            , l = e("../StreamProvider.cjs")
            , d = e("../utils.cjs")
            , f = (0,
            o.detect)()
    }
        , {
            "../MetaMaskInpageProvider.cjs": 91,
            "../StreamProvider.cjs": 92,
            "../utils.cjs": 101,
            "./external-extension-config.json": 95,
            "@metamask/object-multiplex": 58,
            "detect-browser": 199,
            "extension-port-stream": 125,
            "readable-stream": 226
        }],
    95: [function(e, t, r) {
        t.exports = {
            chromeIds: {
                stable: "nkbihfbeogaeaoehlefnkodbefgpgknn",
                beta: "pbbkamfgmaedccnfkmjcofcecjhfgldn",
                flask: "ljfoeinjpaedjfecbmggjgodbgkmjkjk"
            },
            edgeChromiumIds: {
                stable: "ejbalbakoplchlghecdalmeeeajnimhm"
            },
            firefoxIds: {
                stable: "webextension@metamask.io",
                beta: "webextension-beta@metamask.io",
                flask: "webextension-flask@metamask.io"
            }
        }
    }
        , {}],
    96: [function(e, t, r) {
        "use strict";
        var n = this && this.__importDefault || function(e) {
                return e && e.__esModule ? e : {
                    default: e
                }
            }
        ;
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.initializeProvider = function({connectionStream: e, jsonRpcStreamName: t=u.MetaMaskInpageProviderStreamName, logger: r=console, maxEventListeners: n=100, providerInfo: i, shouldSendMetadata: c=!0, shouldSetOnWindow: p=!0, shouldShimWeb3: h=!1}) {
                const g = new s.default;
                (0,
                    o.pipeline)(e, g, e, (e => {
                        let r = `Lost connection to "${t}".`;
                        e?.stack && (r += `\n${e.stack}`),
                            console.warn(r)
                    }
                ));
                const m = new u.MetaMaskInpageProvider(g.createStream(t),{
                    logger: r,
                    maxEventListeners: n,
                    shouldSendMetadata: c
                })
                    , b = new Proxy(m,{
                    deleteProperty: () => !0,
                    get: (e, t) => e[t]
                });
                i && ((0,
                    a.announceProvider)({
                    info: i,
                    provider: b
                }),
                    f(m, i));
                p && d(b);
                h && (0,
                    l.shimWeb3)(b, r);
                return b
            }
            ,
            r.setGlobalProvider = d,
            r.announceCaip294WalletData = f;
        const s = n(e("@metamask/object-multiplex"))
            , o = e("readable-stream")
            , i = e("./CAIP294.cjs")
            , a = e("./EIP6963.cjs")
            , c = e("./extension-provider/createExternalExtensionProvider.cjs")
            , u = e("./MetaMaskInpageProvider.cjs")
            , l = e("./shimWeb3.cjs");
        function d(e) {
            window.ethereum = e,
                window.dispatchEvent(new Event("ethereum#initialized"))
        }
        async function f(e, t) {
            if ("flask" !== (0,
                c.getBuildType)(t.rdns))
                return;
            const r = await e.request({
                method: "metamask_getProviderState"
            })
                , n = r?.extensionId
                , s = {
                ...t,
                extensionId: n
            };
            (0,
                i.announceWallet)(s)
        }
    }
        , {
            "./CAIP294.cjs": 89,
            "./EIP6963.cjs": 90,
            "./MetaMaskInpageProvider.cjs": 91,
            "./extension-provider/createExternalExtensionProvider.cjs": 94,
            "./shimWeb3.cjs": 99,
            "@metamask/object-multiplex": 58,
            "readable-stream": 226
        }],
    97: [function(e, t, r) {
        "use strict";
        Object.defineProperty(r, "__esModule", {
            value: !0
        });
        const n = {
            errors: {
                disconnected: () => "MetaMask: Disconnected from chain. Attempting to connect.",
                permanentlyDisconnected: () => "MetaMask: Disconnected from MetaMask background. Page reload required.",
                sendSiteMetadata: () => "MetaMask: Failed to send site metadata. This is an internal error, please report this bug.",
                unsupportedSync: e => `MetaMask: The MetaMask Ethereum provider does not support synchronous methods like ${e} without a callback parameter.`,
                invalidDuplexStream: () => "Must provide a Node.js-style duplex stream.",
                invalidNetworkParams: () => "MetaMask: Received invalid network parameters. Please report this bug.",
                invalidRequestArgs: () => "Expected a single, non-array, object argument.",
                invalidRequestMethod: () => "'args.method' must be a non-empty string.",
                invalidRequestParams: () => "'args.params' must be an object or array if provided.",
                invalidLoggerObject: () => "'args.logger' must be an object if provided.",
                invalidLoggerMethod: e => `'args.logger' must include required method '${e}'.`
            },
            info: {
                connected: e => `MetaMask: Connected to chain with ID "${e}".`
            },
            warnings: {
                enableDeprecation: "MetaMask: 'ethereum.enable()' is deprecated and may be removed in the future. Please use the 'eth_requestAccounts' RPC method instead.\nFor more information, see: https://eips.ethereum.org/EIPS/eip-1102",
                sendDeprecation: "MetaMask: 'ethereum.send(...)' is deprecated and may be removed in the future. Please use 'ethereum.sendAsync(...)' or 'ethereum.request(...)' instead.\nFor more information, see: https://eips.ethereum.org/EIPS/eip-1193",
                events: {
                    close: "MetaMask: The event 'close' is deprecated and may be removed in the future. Please use 'disconnect' instead.\nFor more information, see: https://eips.ethereum.org/EIPS/eip-1193#disconnect",
                    data: "MetaMask: The event 'data' is deprecated and will be removed in the future. Use 'message' instead.\nFor more information, see: https://eips.ethereum.org/EIPS/eip-1193#message",
                    networkChanged: "MetaMask: The event 'networkChanged' is deprecated and may be removed in the future. Use 'chainChanged' instead.\nFor more information, see: https://eips.ethereum.org/EIPS/eip-1193#chainchanged",
                    notification: "MetaMask: The event 'notification' is deprecated and may be removed in the future. Use 'message' instead.\nFor more information, see: https://eips.ethereum.org/EIPS/eip-1193#message"
                },
                rpc: {
                    ethDecryptDeprecation: "MetaMask: The RPC method 'eth_decrypt' is deprecated and may be removed in the future.\nFor more information, see: https://medium.com/metamask/metamask-api-method-deprecation-2b0564a84686",
                    ethGetEncryptionPublicKeyDeprecation: "MetaMask: The RPC method 'eth_getEncryptionPublicKey' is deprecated and may be removed in the future.\nFor more information, see: https://medium.com/metamask/metamask-api-method-deprecation-2b0564a84686",
                    walletWatchAssetNFTExperimental: "MetaMask: The RPC method 'wallet_watchAsset' is experimental for ERC721/ERC1155 assets and may change in the future.\nFor more information, see: https://github.com/MetaMask/metamask-improvement-proposals/blob/main/MIPs/mip-1.md and https://github.com/MetaMask/metamask-improvement-proposals/blob/main/PROCESS-GUIDE.md#proposal-lifecycle"
                },
                experimentalMethods: "MetaMask: 'ethereum._metamask' exposes non-standard, experimental methods. They may be removed or changed without warning."
            }
        };
        r.default = n
    }
        , {}],
    98: [function(e, t, r) {
        "use strict";
        var n = this && this.__importDefault || function(e) {
                return e && e.__esModule ? e : {
                    default: e
                }
            }
        ;
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.createRpcWarningMiddleware = function(e) {
                const t = {
                    ethDecryptDeprecation: !1,
                    ethGetEncryptionPublicKeyDeprecation: !1,
                    walletWatchAssetNFTExperimental: !1
                };
                return (r, n, i) => {
                    t.ethDecryptDeprecation || "eth_decrypt" !== r.method ? t.ethGetEncryptionPublicKeyDeprecation || "eth_getEncryptionPublicKey" !== r.method ? !t.walletWatchAssetNFTExperimental && "wallet_watchAsset" === r.method && [s.ERC721, s.ERC1155].includes(r.params?.type || "") && (e.warn(o.default.warnings.rpc.walletWatchAssetNFTExperimental),
                        t.walletWatchAssetNFTExperimental = !0) : (e.warn(o.default.warnings.rpc.ethGetEncryptionPublicKeyDeprecation),
                        t.ethGetEncryptionPublicKeyDeprecation = !0) : (e.warn(o.default.warnings.rpc.ethDecryptDeprecation),
                        t.ethDecryptDeprecation = !0),
                        i()
                }
            }
        ;
        const s = e("../constants.cjs")
            , o = n(e("../messages.cjs"))
    }
        , {
            "../constants.cjs": 93,
            "../messages.cjs": 97
        }],
    99: [function(e, t, r) {
        "use strict";
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.shimWeb3 = function(e, t=console) {
                let r = !1
                    , n = !1;
                if (!window.web3) {
                    const s = "__isMetaMaskShim__";
                    let o = {
                        currentProvider: e
                    };
                    Object.defineProperty(o, s, {
                        value: !0,
                        enumerable: !0,
                        configurable: !1,
                        writable: !1
                    }),
                        o = new Proxy(o,{
                            get: (o, i, ...a) => ("currentProvider" !== i || r ? "currentProvider" === i || i === s || n || (n = !0,
                                t.error("MetaMask no longer injects web3. For details, see: https://docs.metamask.io/guide/provider-migration.html#replacing-window-web3"),
                                e.request({
                                    method: "metamask_logWeb3ShimUsage"
                                }).catch((e => {
                                        t.debug("MetaMask: Failed to log web3 shim usage.", e)
                                    }
                                ))) : (r = !0,
                                t.warn("You are accessing the MetaMask window.web3.currentProvider shim. This property is deprecated; use window.ethereum instead. For details, see: https://docs.metamask.io/guide/provider-migration.html#replacing-window-web3")),
                                Reflect.get(o, i, ...a)),
                            set: (...e) => (t.warn("You are accessing the MetaMask window.web3 shim. This object is deprecated; use window.ethereum instead. For details, see: https://docs.metamask.io/guide/provider-migration.html#replacing-window-web3"),
                                Reflect.set(...e))
                        }),
                        Object.defineProperty(window, "web3", {
                            value: o,
                            enumerable: !1,
                            configurable: !0,
                            writable: !0
                        })
                }
            }
    }
        , {}],
    100: [function(e, t, r) {
        "use strict";
        var n = this && this.__importDefault || function(e) {
                return e && e.__esModule ? e : {
                    default: e
                }
            }
        ;
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.sendSiteMetadata = async function(e, t) {
                try {
                    const t = await async function() {
                        return {
                            name: i(window),
                            icon: await a(window)
                        }
                    }();
                    e.handle({
                        jsonrpc: "2.0",
                        id: 1,
                        method: "metamask_sendDomainMetadata",
                        params: t
                    }, o.NOOP)
                } catch (e) {
                    t.error({
                        message: s.default.errors.sendSiteMetadata(),
                        originalError: e
                    })
                }
            }
        ;
        const s = n(e("./messages.cjs"))
            , o = e("./utils.cjs");
        function i(e) {
            const {document: t} = e
                , r = t.querySelector('head > meta[property="og:site_name"]');
            if (r)
                return r.content;
            const n = t.querySelector('head > meta[name="title"]');
            return n ? n.content : t.title && t.title.length > 0 ? t.title : window.location.hostname
        }
        async function a(e) {
            const {document: t} = e
                , r = t.querySelectorAll('head > link[rel~="icon"]');
            for (const e of Array.from(r))
                if (e && await c(e.href))
                    return e.href;
            return null
        }
        async function c(e) {
            return new Promise(( (t, r) => {
                    try {
                        const r = document.createElement("img");
                        r.onload = () => t(!0),
                            r.onerror = () => t(!1),
                            r.src = e
                    } catch (e) {
                        r(e)
                    }
                }
            ))
        }
    }
        , {
            "./messages.cjs": 97,
            "./utils.cjs": 101
        }],
    101: [function(e, t, r) {
        "use strict";
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.NOOP = r.isValidNetworkVersion = r.isValidChainId = r.getRpcPromiseCallback = r.getDefaultExternalMiddleware = r.EMITTED_NOTIFICATIONS = r.FQDN_REGEX = r.UUID_V4_REGEX = void 0;
        const n = e("@metamask/json-rpc-engine")
            , s = e("@metamask/rpc-errors")
            , o = e("./middleware/createRpcWarningMiddleware.cjs");
        r.UUID_V4_REGEX = /(?:^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[a-f0-9]{4}-[a-f0-9]{12}$)|(?:^0{8}-0{4}-0{4}-0{4}-0{12}$)/u,
            r.FQDN_REGEX = /(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{0,62}[a-zA-Z0-9]\.)+[a-zA-Z]{2,63}$)/u;
        const i = /^(\d*[1-9]\d*|0)$/u;
        r.EMITTED_NOTIFICATIONS = Object.freeze(["eth_subscription"]);
        r.getDefaultExternalMiddleware = (e=console) => {
            return [(0,
                n.createIdRemapMiddleware)(), (t = e,
                    (e, r, n) => {
                        "string" == typeof e.method && e.method || (r.error = s.rpcErrors.invalidRequest({
                            message: "The request 'method' must be a non-empty string.",
                            data: e
                        })),
                            n((e => {
                                    const {error: n} = r;
                                    return n ? (t.warn(`MetaMask - RPC Error: ${n.message}`, n),
                                        e()) : e()
                                }
                            ))
                    }
            ), (0,
                o.createRpcWarningMiddleware)(e)];
            var t
        }
        ;
        r.getRpcPromiseCallback = (e, t, r=!0) => (n, s) => {
            n || s.error ? t(n || s.error) : !r || Array.isArray(s) ? e(s) : e(s.result)
        }
        ;
        r.isValidChainId = e => Boolean(e) && "string" == typeof e && e.startsWith("0x");
        r.isValidNetworkVersion = e => "string" == typeof e && (i.test(e) || "loading" === e);
        r.NOOP = () => {}
    }
        , {
            "./middleware/createRpcWarningMiddleware.cjs": 98,
            "@metamask/json-rpc-engine": 7,
            "@metamask/rpc-errors": 153
        }],
    102: [function(e, t, r) {
        t.exports = e("./dist/initializeInpageProvider.cjs")
    }
        , {
            "./dist/initializeInpageProvider.cjs": 96
        }],
    103: [function(e, t, r) {
        arguments[4][9][0].apply(r, arguments)
    }
        , {
            "./errors.cjs": 111,
            "@metamask/superstruct": 179,
            dup: 9
        }],
    104: [function(e, t, r) {
        arguments[4][10][0].apply(r, arguments)
    }
        , {
            "./assert.cjs": 103,
            "@metamask/superstruct": 179,
            dup: 10
        }],
    105: [function(e, t, r) {
        (function(t) {
                (function() {
                        "use strict";
                        Object.defineProperty(r, "__esModule", {
                            value: !0
                        }),
                            r.createDataView = r.concatBytes = r.valueToBytes = r.base64ToBytes = r.stringToBytes = r.numberToBytes = r.signedBigIntToBytes = r.bigIntToBytes = r.hexToBytes = r.bytesToBase64 = r.bytesToString = r.bytesToNumber = r.bytesToSignedBigInt = r.bytesToBigInt = r.bytesToHex = r.assertIsBytes = r.isBytes = void 0;
                        const n = e("@scure/base")
                            , s = e("./assert.cjs")
                            , o = e("./hex.cjs")
                            , i = 48
                            , a = 58
                            , c = 87;
                        const u = function() {
                            const e = [];
                            return () => {
                                if (0 === e.length)
                                    for (let t = 0; t < 256; t++)
                                        e.push(t.toString(16).padStart(2, "0"));
                                return e
                            }
                        }();
                        function l(e) {
                            return e instanceof Uint8Array
                        }
                        function d(e) {
                            (0,
                                s.assert)(l(e), "Value must be a Uint8Array.")
                        }
                        function f(e) {
                            if (d(e),
                            0 === e.length)
                                return "0x";
                            const t = u()
                                , r = new Array(e.length);
                            for (let n = 0; n < e.length; n++)
                                r[n] = t[e[n]];
                            return (0,
                                o.add0x)(r.join(""))
                        }
                        function p(e) {
                            d(e);
                            const t = f(e);
                            return BigInt(t)
                        }
                        function h(e) {
                            if ("0x" === e?.toLowerCase?.())
                                return new Uint8Array;
                            (0,
                                o.assertIsHexString)(e);
                            const t = (0,
                                o.remove0x)(e).toLowerCase()
                                , r = t.length % 2 == 0 ? t : `0${t}`
                                , n = new Uint8Array(r.length / 2);
                            for (let e = 0; e < n.length; e++) {
                                const t = r.charCodeAt(2 * e)
                                    , s = r.charCodeAt(2 * e + 1)
                                    , o = t - (t < a ? i : c)
                                    , u = s - (s < a ? i : c);
                                n[e] = 16 * o + u
                            }
                            return n
                        }
                        function g(e) {
                            (0,
                                s.assert)("bigint" == typeof e, "Value must be a bigint."),
                                (0,
                                    s.assert)(e >= BigInt(0), "Value must be a non-negative bigint.");
                            return h(e.toString(16))
                        }
                        function m(e) {
                            (0,
                                s.assert)("number" == typeof e, "Value must be a number."),
                                (0,
                                    s.assert)(e >= 0, "Value must be a non-negative number."),
                                (0,
                                    s.assert)(Number.isSafeInteger(e), "Value is not a safe integer. Use `bigIntToBytes` instead.");
                            return h(e.toString(16))
                        }
                        function b(e) {
                            return (0,
                                s.assert)("string" == typeof e, "Value must be a string."),
                                (new TextEncoder).encode(e)
                        }
                        function y(e) {
                            if ("bigint" == typeof e)
                                return g(e);
                            if ("number" == typeof e)
                                return m(e);
                            if ("string" == typeof e)
                                return e.startsWith("0x") ? h(e) : b(e);
                            if (l(e))
                                return e;
                            throw new TypeError(`Unsupported value type: "${typeof e}".`)
                        }
                        r.isBytes = l,
                            r.assertIsBytes = d,
                            r.bytesToHex = f,
                            r.bytesToBigInt = p,
                            r.bytesToSignedBigInt = function(e) {
                                d(e);
                                let t = BigInt(0);
                                for (const r of e)
                                    t = (t << BigInt(8)) + BigInt(r);
                                return BigInt.asIntN(8 * e.length, t)
                            }
                            ,
                            r.bytesToNumber = function(e) {
                                d(e);
                                const t = p(e);
                                return (0,
                                    s.assert)(t <= BigInt(Number.MAX_SAFE_INTEGER), "Number is not a safe integer. Use `bytesToBigInt` instead."),
                                    Number(t)
                            }
                            ,
                            r.bytesToString = function(e) {
                                return d(e),
                                    (new TextDecoder).decode(e)
                            }
                            ,
                            r.bytesToBase64 = function(e) {
                                return d(e),
                                    n.base64.encode(e)
                            }
                            ,
                            r.hexToBytes = h,
                            r.bigIntToBytes = g,
                            r.signedBigIntToBytes = function(e, t) {
                                (0,
                                    s.assert)("bigint" == typeof e, "Value must be a bigint."),
                                    (0,
                                        s.assert)("number" == typeof t, "Byte length must be a number."),
                                    (0,
                                        s.assert)(t > 0, "Byte length must be greater than 0."),
                                    (0,
                                        s.assert)(function(e, t) {
                                        (0,
                                            s.assert)(t > 0);
                                        const r = e >> BigInt(31);
                                        return !((~e & r) + (e & ~r) >> BigInt(8 * t - 1))
                                    }(e, t), "Byte length is too small to represent the given value.");
                                let r = e;
                                const n = new Uint8Array(t);
                                for (let e = 0; e < n.length; e++)
                                    n[e] = Number(BigInt.asUintN(8, r)),
                                        r >>= BigInt(8);
                                return n.reverse()
                            }
                            ,
                            r.numberToBytes = m,
                            r.stringToBytes = b,
                            r.base64ToBytes = function(e) {
                                return (0,
                                    s.assert)("string" == typeof e, "Value must be a string."),
                                    n.base64.decode(e)
                            }
                            ,
                            r.valueToBytes = y,
                            r.concatBytes = function(e) {
                                const t = new Array(e.length);
                                let r = 0;
                                for (let n = 0; n < e.length; n++) {
                                    const s = y(e[n]);
                                    t[n] = s,
                                        r += s.length
                                }
                                const n = new Uint8Array(r);
                                for (let e = 0, r = 0; e < t.length; e++)
                                    n.set(t[e], r),
                                        r += t[e].length;
                                return n
                            }
                            ,
                            r.createDataView = function(e) {
                                if (void 0 !== t && e instanceof t) {
                                    const t = e.buffer.slice(e.byteOffset, e.byteOffset + e.byteLength);
                                    return new DataView(t)
                                }
                                return new DataView(e.buffer,e.byteOffset,e.byteLength)
                            }
                    }
                ).call(this)
            }
        ).call(this, e("buffer").Buffer)
    }
        , {
            "./assert.cjs": 103,
            "./hex.cjs": 112,
            "@scure/base": 191,
            buffer: 195
        }],
    106: [function(e, t, r) {
        arguments[4][12][0].apply(r, arguments)
    }
        , {
            "./superstruct.cjs": 121,
            "@metamask/superstruct": 179,
            dup: 12
        }],
    107: [function(e, t, r) {
        arguments[4][13][0].apply(r, arguments)
    }
        , {
            "./base64.cjs": 104,
            "@metamask/superstruct": 179,
            dup: 13
        }],
    108: [function(e, t, r) {
        arguments[4][14][0].apply(r, arguments)
    }
        , {
            "./assert.cjs": 103,
            "./bytes.cjs": 105,
            "./hex.cjs": 112,
            "@metamask/superstruct": 179,
            dup: 14
        }],
    109: [function(e, t, r) {
        arguments[4][15][0].apply(r, arguments)
    }
        , {
            dup: 15
        }],
    110: [function(e, t, r) {
        arguments[4][16][0].apply(r, arguments)
    }
        , {
            dup: 16
        }],
    111: [function(e, t, r) {
        arguments[4][17][0].apply(r, arguments)
    }
        , {
            "./misc.cjs": 117,
            dup: 17,
            "pony-cause": 208
        }],
    112: [function(e, t, r) {
        arguments[4][18][0].apply(r, arguments)
    }
        , {
            "./assert.cjs": 103,
            "./bytes.cjs": 105,
            "@metamask/superstruct": 179,
            "@noble/hashes/sha3": 189,
            dup: 18
        }],
    113: [function(e, t, r) {
        arguments[4][19][0].apply(r, arguments)
    }
        , {
            "./assert.cjs": 103,
            "./base64.cjs": 104,
            "./bytes.cjs": 105,
            "./caip-types.cjs": 106,
            "./checksum.cjs": 107,
            "./coercers.cjs": 108,
            "./collections.cjs": 109,
            "./encryption-types.cjs": 110,
            "./errors.cjs": 111,
            "./hex.cjs": 112,
            "./json.cjs": 114,
            "./keyring.cjs": 115,
            "./logging.cjs": 116,
            "./misc.cjs": 117,
            "./number.cjs": 118,
            "./opaque.cjs": 119,
            "./promise.cjs": 120,
            "./superstruct.cjs": 121,
            "./time.cjs": 122,
            "./transaction-types.cjs": 123,
            "./versions.cjs": 124,
            dup: 19
        }],
    114: [function(e, t, r) {
        arguments[4][20][0].apply(r, arguments)
    }
        , {
            "./assert.cjs": 103,
            "./misc.cjs": 117,
            "@metamask/superstruct": 179,
            dup: 20
        }],
    115: [function(e, t, r) {
        arguments[4][21][0].apply(r, arguments)
    }
        , {
            dup: 21
        }],
    116: [function(e, t, r) {
        arguments[4][22][0].apply(r, arguments)
    }
        , {
            debug: 197,
            dup: 22
        }],
    117: [function(e, t, r) {
        arguments[4][23][0].apply(r, arguments)
    }
        , {
            dup: 23
        }],
    118: [function(e, t, r) {
        arguments[4][24][0].apply(r, arguments)
    }
        , {
            "./assert.cjs": 103,
            "./hex.cjs": 112,
            dup: 24
        }],
    119: [function(e, t, r) {
        arguments[4][25][0].apply(r, arguments)
    }
        , {
            dup: 25
        }],
    120: [function(e, t, r) {
        arguments[4][26][0].apply(r, arguments)
    }
        , {
            dup: 26
        }],
    121: [function(e, t, r) {
        arguments[4][27][0].apply(r, arguments)
    }
        , {
            "@metamask/superstruct": 179,
            dup: 27
        }],
    122: [function(e, t, r) {
        arguments[4][28][0].apply(r, arguments)
    }
        , {
            dup: 28
        }],
    123: [function(e, t, r) {
        arguments[4][29][0].apply(r, arguments)
    }
        , {
            dup: 29
        }],
    124: [function(e, t, r) {
        arguments[4][30][0].apply(r, arguments)
    }
        , {
            "./assert.cjs": 103,
            "@metamask/superstruct": 179,
            dup: 30,
            semver: 255
        }],
    125: [function(e, t, r) {
        (function(t) {
                (function() {
                        "use strict";
                        Object.defineProperty(r, "__esModule", {
                            value: !0
                        }),
                            r.PortDuplexStream = void 0;
                        const n = e("readable-stream");
                        class s extends n.Duplex {
                            constructor(e, t={}) {
                                super(Object.assign({
                                    objectMode: !0
                                }, t)),
                                    this._port = e,
                                    this._port.onMessage.addListener((e => this._onMessage(e))),
                                    this._port.onDisconnect.addListener(( () => this._onDisconnect())),
                                    this._log = () => null
                            }
                            _onMessage(e) {
                                if (t.isBuffer(e)) {
                                    const r = t.from(e);
                                    this._log(r, !1),
                                        this.push(r)
                                } else
                                    this._log(e, !1),
                                        this.push(e)
                            }
                            _onDisconnect() {
                                this.destroy()
                            }
                            _read() {}
                            _write(e, r, n) {
                                try {
                                    if (t.isBuffer(e)) {
                                        const t = e.toJSON();
                                        t._isBuffer = !0,
                                            this._log(t, !0),
                                            this._port.postMessage(t)
                                    } else
                                        this._log(e, !0),
                                            this._port.postMessage(e)
                                } catch (e) {
                                    return n(new Error("PortDuplexStream - disconnected"))
                                }
                                return n()
                            }
                            _setLogger(e) {
                                this._log = e
                            }
                        }
                        r.default = s,
                            r.PortDuplexStream = s
                    }
                ).call(this)
            }
        ).call(this, e("buffer").Buffer)
    }
        , {
            buffer: 195,
            "readable-stream": 144
        }],
    126: [function(e, t, r) {
        "use strict";
        const {SymbolDispose: n} = e("../../ours/primordials")
            , {AbortError: s, codes: o} = e("../../ours/errors")
            , {isNodeStream: i, isWebStream: a, kControllerErrorFunction: c} = e("./utils")
            , u = e("./end-of-stream")
            , {ERR_INVALID_ARG_TYPE: l} = o;
        let d;
        t.exports.addAbortSignal = function(e, r) {
            if (( (e, t) => {
                    if ("object" != typeof e || !("aborted"in e))
                        throw new l(t,"AbortSignal",e)
                }
            )(e, "signal"),
            !i(r) && !a(r))
                throw new l("stream",["ReadableStream", "WritableStream", "Stream"],r);
            return t.exports.addAbortSignalNoValidate(e, r)
        }
            ,
            t.exports.addAbortSignalNoValidate = function(t, r) {
                if ("object" != typeof t || !("aborted"in t))
                    return r;
                const o = i(r) ? () => {
                            r.destroy(new s(void 0,{
                                cause: t.reason
                            }))
                        }
                        : () => {
                            r[c](new s(void 0,{
                                cause: t.reason
                            }))
                        }
                ;
                if (t.aborted)
                    o();
                else {
                    d = d || e("../../ours/util").addAbortListener;
                    const s = d(t, o);
                    u(r, s[n])
                }
                return r
            }
    }
        , {
            "../../ours/errors": 145,
            "../../ours/primordials": 146,
            "../../ours/util": 147,
            "./end-of-stream": 132,
            "./utils": 141
        }],
    127: [function(e, t, r) {
        "use strict";
        const {StringPrototypeSlice: n, SymbolIterator: s, TypedArrayPrototypeSet: o, Uint8Array: i} = e("../../ours/primordials")
            , {Buffer: a} = e("buffer")
            , {inspect: c} = e("../../ours/util");
        t.exports = class {
            constructor() {
                this.head = null,
                    this.tail = null,
                    this.length = 0
            }
            push(e) {
                const t = {
                    data: e,
                    next: null
                };
                this.length > 0 ? this.tail.next = t : this.head = t,
                    this.tail = t,
                    ++this.length
            }
            unshift(e) {
                const t = {
                    data: e,
                    next: this.head
                };
                0 === this.length && (this.tail = t),
                    this.head = t,
                    ++this.length
            }
            shift() {
                if (0 === this.length)
                    return;
                const e = this.head.data;
                return 1 === this.length ? this.head = this.tail = null : this.head = this.head.next,
                    --this.length,
                    e
            }
            clear() {
                this.head = this.tail = null,
                    this.length = 0
            }
            join(e) {
                if (0 === this.length)
                    return "";
                let t = this.head
                    , r = "" + t.data;
                for (; null !== (t = t.next); )
                    r += e + t.data;
                return r
            }
            concat(e) {
                if (0 === this.length)
                    return a.alloc(0);
                const t = a.allocUnsafe(e >>> 0);
                let r = this.head
                    , n = 0;
                for (; r; )
                    o(t, r.data, n),
                        n += r.data.length,
                        r = r.next;
                return t
            }
            consume(e, t) {
                const r = this.head.data;
                if (e < r.length) {
                    const t = r.slice(0, e);
                    return this.head.data = r.slice(e),
                        t
                }
                return e === r.length ? this.shift() : t ? this._getString(e) : this._getBuffer(e)
            }
            first() {
                return this.head.data
            }
            *[s]() {
                for (let e = this.head; e; e = e.next)
                    yield e.data
            }
            _getString(e) {
                let t = ""
                    , r = this.head
                    , s = 0;
                do {
                    const o = r.data;
                    if (!(e > o.length)) {
                        e === o.length ? (t += o,
                            ++s,
                            r.next ? this.head = r.next : this.head = this.tail = null) : (t += n(o, 0, e),
                            this.head = r,
                            r.data = n(o, e));
                        break
                    }
                    t += o,
                        e -= o.length,
                        ++s
                } while (null !== (r = r.next));
                return this.length -= s,
                    t
            }
            _getBuffer(e) {
                const t = a.allocUnsafe(e)
                    , r = e;
                let n = this.head
                    , s = 0;
                do {
                    const a = n.data;
                    if (!(e > a.length)) {
                        e === a.length ? (o(t, a, r - e),
                            ++s,
                            n.next ? this.head = n.next : this.head = this.tail = null) : (o(t, new i(a.buffer,a.byteOffset,e), r - e),
                            this.head = n,
                            n.data = a.slice(e));
                        break
                    }
                    o(t, a, r - e),
                        e -= a.length,
                        ++s
                } while (null !== (n = n.next));
                return this.length -= s,
                    t
            }
            [Symbol.for("nodejs.util.inspect.custom")](e, t) {
                return c(this, {
                    ...t,
                    depth: 0,
                    customInspect: !1
                })
            }
        }
    }
        , {
            "../../ours/primordials": 146,
            "../../ours/util": 147,
            buffer: 195
        }],
    128: [function(e, t, r) {
        "use strict";
        const {pipeline: n} = e("./pipeline")
            , s = e("./duplex")
            , {destroyer: o} = e("./destroy")
            , {isNodeStream: i, isReadable: a, isWritable: c, isWebStream: u, isTransformStream: l, isWritableStream: d, isReadableStream: f} = e("./utils")
            , {AbortError: p, codes: {ERR_INVALID_ARG_VALUE: h, ERR_MISSING_ARGS: g}} = e("../../ours/errors")
            , m = e("./end-of-stream");
        t.exports = function(...e) {
            if (0 === e.length)
                throw new g("streams");
            if (1 === e.length)
                return s.from(e[0]);
            const t = [...e];
            if ("function" == typeof e[0] && (e[0] = s.from(e[0])),
            "function" == typeof e[e.length - 1]) {
                const t = e.length - 1;
                e[t] = s.from(e[t])
            }
            for (let r = 0; r < e.length; ++r)
                if (i(e[r]) || u(e[r])) {
                    if (r < e.length - 1 && !(a(e[r]) || f(e[r]) || l(e[r])))
                        throw new h(`streams[${r}]`,t[r],"must be readable");
                    if (r > 0 && !(c(e[r]) || d(e[r]) || l(e[r])))
                        throw new h(`streams[${r}]`,t[r],"must be writable")
                }
            let r, b, y, w, v;
            const _ = e[0]
                , E = n(e, (function(e) {
                    const t = w;
                    w = null,
                        t ? t(e) : e ? v.destroy(e) : j || S || v.destroy()
                }
            ))
                , S = !!(c(_) || d(_) || l(_))
                , j = !!(a(E) || f(E) || l(E));
            if (v = new s({
                writableObjectMode: !(null == _ || !_.writableObjectMode),
                readableObjectMode: !(null == E || !E.readableObjectMode),
                writable: S,
                readable: j
            }),
                S) {
                if (i(_))
                    v._write = function(e, t, n) {
                        _.write(e, t) ? n() : r = n
                    }
                        ,
                        v._final = function(e) {
                            _.end(),
                                b = e
                        }
                        ,
                        _.on("drain", (function() {
                                if (r) {
                                    const e = r;
                                    r = null,
                                        e()
                                }
                            }
                        ));
                else if (u(_)) {
                    const e = (l(_) ? _.writable : _).getWriter();
                    v._write = async function(t, r, n) {
                        try {
                            await e.ready,
                                e.write(t).catch(( () => {}
                                )),
                                n()
                        } catch (e) {
                            n(e)
                        }
                    }
                        ,
                        v._final = async function(t) {
                            try {
                                await e.ready,
                                    e.close().catch(( () => {}
                                    )),
                                    b = t
                            } catch (e) {
                                t(e)
                            }
                        }
                }
                const e = l(E) ? E.readable : E;
                m(e, ( () => {
                        if (b) {
                            const e = b;
                            b = null,
                                e()
                        }
                    }
                ))
            }
            if (j)
                if (i(E))
                    E.on("readable", (function() {
                            if (y) {
                                const e = y;
                                y = null,
                                    e()
                            }
                        }
                    )),
                        E.on("end", (function() {
                                v.push(null)
                            }
                        )),
                        v._read = function() {
                            for (; ; ) {
                                const e = E.read();
                                if (null === e)
                                    return void (y = v._read);
                                if (!v.push(e))
                                    return
                            }
                        }
                    ;
                else if (u(E)) {
                    const e = (l(E) ? E.readable : E).getReader();
                    v._read = async function() {
                        for (; ; )
                            try {
                                const {value: t, done: r} = await e.read();
                                if (!v.push(t))
                                    return;
                                if (r)
                                    return void v.push(null)
                            } catch {
                                return
                            }
                    }
                }
            return v._destroy = function(e, t) {
                e || null === w || (e = new p),
                    y = null,
                    r = null,
                    b = null,
                    null === w ? t(e) : (w = t,
                    i(E) && o(E, e))
            }
                ,
                v
        }
    }
        , {
            "../../ours/errors": 145,
            "./destroy": 129,
            "./duplex": 130,
            "./end-of-stream": 132,
            "./pipeline": 137,
            "./utils": 141
        }],
    129: [function(e, t, r) {
        "use strict";
        const n = e("process/")
            , {aggregateTwoErrors: s, codes: {ERR_MULTIPLE_CALLBACK: o}, AbortError: i} = e("../../ours/errors")
            , {Symbol: a} = e("../../ours/primordials")
            , {kIsDestroyed: c, isDestroyed: u, isFinished: l, isServerRequest: d} = e("./utils")
            , f = a("kDestroy")
            , p = a("kConstruct");
        function h(e, t, r) {
            e && (e.stack,
            t && !t.errored && (t.errored = e),
            r && !r.errored && (r.errored = e))
        }
        function g(e, t, r) {
            let s = !1;
            function o(t) {
                if (s)
                    return;
                s = !0;
                const o = e._readableState
                    , i = e._writableState;
                h(t, i, o),
                i && (i.closed = !0),
                o && (o.closed = !0),
                "function" == typeof r && r(t),
                    t ? n.nextTick(m, e, t) : n.nextTick(b, e)
            }
            try {
                e._destroy(t || null, o)
            } catch (t) {
                o(t)
            }
        }
        function m(e, t) {
            y(e, t),
                b(e)
        }
        function b(e) {
            const t = e._readableState
                , r = e._writableState;
            r && (r.closeEmitted = !0),
            t && (t.closeEmitted = !0),
            (null != r && r.emitClose || null != t && t.emitClose) && e.emit("close")
        }
        function y(e, t) {
            const r = e._readableState
                , n = e._writableState;
            null != n && n.errorEmitted || null != r && r.errorEmitted || (n && (n.errorEmitted = !0),
            r && (r.errorEmitted = !0),
                e.emit("error", t))
        }
        function w(e, t, r) {
            const s = e._readableState
                , o = e._writableState;
            if (null != o && o.destroyed || null != s && s.destroyed)
                return this;
            null != s && s.autoDestroy || null != o && o.autoDestroy ? e.destroy(t) : t && (t.stack,
            o && !o.errored && (o.errored = t),
            s && !s.errored && (s.errored = t),
                r ? n.nextTick(y, e, t) : y(e, t))
        }
        function v(e) {
            let t = !1;
            function r(r) {
                if (t)
                    return void w(e, null != r ? r : new o);
                t = !0;
                const s = e._readableState
                    , i = e._writableState
                    , a = i || s;
                s && (s.constructed = !0),
                i && (i.constructed = !0),
                    a.destroyed ? e.emit(f, r) : r ? w(e, r, !0) : n.nextTick(_, e)
            }
            try {
                e._construct((e => {
                        n.nextTick(r, e)
                    }
                ))
            } catch (e) {
                n.nextTick(r, e)
            }
        }
        function _(e) {
            e.emit(p)
        }
        function E(e) {
            return (null == e ? void 0 : e.setHeader) && "function" == typeof e.abort
        }
        function S(e) {
            e.emit("close")
        }
        function j(e, t) {
            e.emit("error", t),
                n.nextTick(S, e)
        }
        t.exports = {
            construct: function(e, t) {
                if ("function" != typeof e._construct)
                    return;
                const r = e._readableState
                    , s = e._writableState;
                r && (r.constructed = !1),
                s && (s.constructed = !1),
                    e.once(p, t),
                e.listenerCount(p) > 1 || n.nextTick(v, e)
            },
            destroyer: function(e, t) {
                e && !u(e) && (t || l(e) || (t = new i),
                    d(e) ? (e.socket = null,
                        e.destroy(t)) : E(e) ? e.abort() : E(e.req) ? e.req.abort() : "function" == typeof e.destroy ? e.destroy(t) : "function" == typeof e.close ? e.close() : t ? n.nextTick(j, e, t) : n.nextTick(S, e),
                e.destroyed || (e[c] = !0))
            },
            destroy: function(e, t) {
                const r = this._readableState
                    , n = this._writableState
                    , o = n || r;
                return null != n && n.destroyed || null != r && r.destroyed ? ("function" == typeof t && t(),
                    this) : (h(e, n, r),
                n && (n.destroyed = !0),
                r && (r.destroyed = !0),
                    o.constructed ? g(this, e, t) : this.once(f, (function(r) {
                            g(this, s(r, e), t)
                        }
                    )),
                    this)
            },
            undestroy: function() {
                const e = this._readableState
                    , t = this._writableState;
                e && (e.constructed = !0,
                    e.closed = !1,
                    e.closeEmitted = !1,
                    e.destroyed = !1,
                    e.errored = null,
                    e.errorEmitted = !1,
                    e.reading = !1,
                    e.ended = !1 === e.readable,
                    e.endEmitted = !1 === e.readable),
                t && (t.constructed = !0,
                    t.destroyed = !1,
                    t.closed = !1,
                    t.closeEmitted = !1,
                    t.errored = null,
                    t.errorEmitted = !1,
                    t.finalCalled = !1,
                    t.prefinished = !1,
                    t.ended = !1 === t.writable,
                    t.ending = !1 === t.writable,
                    t.finished = !1 === t.writable)
            },
            errorOrDestroy: w
        }
    }
        , {
            "../../ours/errors": 145,
            "../../ours/primordials": 146,
            "./utils": 141,
            "process/": 211
        }],
    130: [function(e, t, r) {
        "use strict";
        const {ObjectDefineProperties: n, ObjectGetOwnPropertyDescriptor: s, ObjectKeys: o, ObjectSetPrototypeOf: i} = e("../../ours/primordials");
        t.exports = u;
        const a = e("./readable")
            , c = e("./writable");
        i(u.prototype, a.prototype),
            i(u, a);
        {
            const e = o(c.prototype);
            for (let t = 0; t < e.length; t++) {
                const r = e[t];
                u.prototype[r] || (u.prototype[r] = c.prototype[r])
            }
        }
        function u(e) {
            if (!(this instanceof u))
                return new u(e);
            a.call(this, e),
                c.call(this, e),
                e ? (this.allowHalfOpen = !1 !== e.allowHalfOpen,
                !1 === e.readable && (this._readableState.readable = !1,
                    this._readableState.ended = !0,
                    this._readableState.endEmitted = !0),
                !1 === e.writable && (this._writableState.writable = !1,
                    this._writableState.ending = !0,
                    this._writableState.ended = !0,
                    this._writableState.finished = !0)) : this.allowHalfOpen = !0
        }
        let l, d;
        function f() {
            return void 0 === l && (l = {}),
                l
        }
        n(u.prototype, {
            writable: {
                __proto__: null,
                ...s(c.prototype, "writable")
            },
            writableHighWaterMark: {
                __proto__: null,
                ...s(c.prototype, "writableHighWaterMark")
            },
            writableObjectMode: {
                __proto__: null,
                ...s(c.prototype, "writableObjectMode")
            },
            writableBuffer: {
                __proto__: null,
                ...s(c.prototype, "writableBuffer")
            },
            writableLength: {
                __proto__: null,
                ...s(c.prototype, "writableLength")
            },
            writableFinished: {
                __proto__: null,
                ...s(c.prototype, "writableFinished")
            },
            writableCorked: {
                __proto__: null,
                ...s(c.prototype, "writableCorked")
            },
            writableEnded: {
                __proto__: null,
                ...s(c.prototype, "writableEnded")
            },
            writableNeedDrain: {
                __proto__: null,
                ...s(c.prototype, "writableNeedDrain")
            },
            destroyed: {
                __proto__: null,
                get() {
                    return void 0 !== this._readableState && void 0 !== this._writableState && (this._readableState.destroyed && this._writableState.destroyed)
                },
                set(e) {
                    this._readableState && this._writableState && (this._readableState.destroyed = e,
                        this._writableState.destroyed = e)
                }
            }
        }),
            u.fromWeb = function(e, t) {
                return f().newStreamDuplexFromReadableWritablePair(e, t)
            }
            ,
            u.toWeb = function(e) {
                return f().newReadableWritablePairFromDuplex(e)
            }
            ,
            u.from = function(t) {
                return d || (d = e("./duplexify")),
                    d(t, "body")
            }
    }
        , {
            "../../ours/primordials": 146,
            "./duplexify": 131,
            "./readable": 138,
            "./writable": 142
        }],
    131: [function(e, t, r) {
        const n = e("process/")
            , s = e("buffer")
            , {isReadable: o, isWritable: i, isIterable: a, isNodeStream: c, isReadableNodeStream: u, isWritableNodeStream: l, isDuplexNodeStream: d, isReadableStream: f, isWritableStream: p} = e("./utils")
            , h = e("./end-of-stream")
            , {AbortError: g, codes: {ERR_INVALID_ARG_TYPE: m, ERR_INVALID_RETURN_VALUE: b}} = e("../../ours/errors")
            , {destroyer: y} = e("./destroy")
            , w = e("./duplex")
            , v = e("./readable")
            , _ = e("./writable")
            , {createDeferredPromise: E} = e("../../ours/util")
            , S = e("./from")
            , j = globalThis.Blob || s.Blob
            , R = void 0 !== j ? function(e) {
                return e instanceof j
            }
            : function(e) {
                return !1
            }
            , I = globalThis.AbortController || e("abort-controller").AbortController
            , {FunctionPrototypeCall: A} = e("../../ours/primordials");
        class M extends w {
            constructor(e) {
                super(e),
                !1 === (null == e ? void 0 : e.readable) && (this._readableState.readable = !1,
                    this._readableState.ended = !0,
                    this._readableState.endEmitted = !0),
                !1 === (null == e ? void 0 : e.writable) && (this._writableState.writable = !1,
                    this._writableState.ending = !0,
                    this._writableState.ended = !0,
                    this._writableState.finished = !0)
            }
        }
        function T(e) {
            const t = e.readable && "function" != typeof e.readable.read ? v.wrap(e.readable) : e.readable
                , r = e.writable;
            let n, s, a, c, u, l = !!o(t), d = !!i(r);
            function f(e) {
                const t = c;
                c = null,
                    t ? t(e) : e && u.destroy(e)
            }
            return u = new M({
                readableObjectMode: !(null == t || !t.readableObjectMode),
                writableObjectMode: !(null == r || !r.writableObjectMode),
                readable: l,
                writable: d
            }),
            d && (h(r, (e => {
                    d = !1,
                    e && y(t, e),
                        f(e)
                }
            )),
                u._write = function(e, t, s) {
                    r.write(e, t) ? s() : n = s
                }
                ,
                u._final = function(e) {
                    r.end(),
                        s = e
                }
                ,
                r.on("drain", (function() {
                        if (n) {
                            const e = n;
                            n = null,
                                e()
                        }
                    }
                )),
                r.on("finish", (function() {
                        if (s) {
                            const e = s;
                            s = null,
                                e()
                        }
                    }
                ))),
            l && (h(t, (e => {
                        l = !1,
                        e && y(t, e),
                            f(e)
                    }
                )),
                    t.on("readable", (function() {
                            if (a) {
                                const e = a;
                                a = null,
                                    e()
                            }
                        }
                    )),
                    t.on("end", (function() {
                            u.push(null)
                        }
                    )),
                    u._read = function() {
                        for (; ; ) {
                            const e = t.read();
                            if (null === e)
                                return void (a = u._read);
                            if (!u.push(e))
                                return
                        }
                    }
            ),
                u._destroy = function(e, o) {
                    e || null === c || (e = new g),
                        a = null,
                        n = null,
                        s = null,
                        null === c ? o(e) : (c = o,
                            y(r, e),
                            y(t, e))
                }
                ,
                u
        }
        t.exports = function e(t, r) {
            if (d(t))
                return t;
            if (u(t))
                return T({
                    readable: t
                });
            if (l(t))
                return T({
                    writable: t
                });
            if (c(t))
                return T({
                    writable: !1,
                    readable: !1
                });
            if (f(t))
                return T({
                    readable: v.fromWeb(t)
                });
            if (p(t))
                return T({
                    writable: _.fromWeb(t)
                });
            if ("function" == typeof t) {
                const {value: e, write: s, final: o, destroy: i} = function(e) {
                    let {promise: t, resolve: r} = E();
                    const s = new I
                        , o = s.signal
                        , i = e(async function*() {
                        for (; ; ) {
                            const e = t;
                            t = null;
                            const {chunk: s, done: i, cb: a} = await e;
                            if (n.nextTick(a),
                                i)
                                return;
                            if (o.aborted)
                                throw new g(void 0,{
                                    cause: o.reason
                                });
                            ({promise: t, resolve: r} = E()),
                                yield s
                        }
                    }(), {
                        signal: o
                    });
                    return {
                        value: i,
                        write(e, t, n) {
                            const s = r;
                            r = null,
                                s({
                                    chunk: e,
                                    done: !1,
                                    cb: n
                                })
                        },
                        final(e) {
                            const t = r;
                            r = null,
                                t({
                                    done: !0,
                                    cb: e
                                })
                        },
                        destroy(e, t) {
                            s.abort(),
                                t(e)
                        }
                    }
                }(t);
                if (a(e))
                    return S(M, e, {
                        objectMode: !0,
                        write: s,
                        final: o,
                        destroy: i
                    });
                const c = null == e ? void 0 : e.then;
                if ("function" == typeof c) {
                    let t;
                    const r = A(c, e, (e => {
                            if (null != e)
                                throw new b("nully","body",e)
                        }
                    ), (e => {
                            y(t, e)
                        }
                    ));
                    return t = new M({
                        objectMode: !0,
                        readable: !1,
                        write: s,
                        final(e) {
                            o((async () => {
                                    try {
                                        await r,
                                            n.nextTick(e, null)
                                    } catch (t) {
                                        n.nextTick(e, t)
                                    }
                                }
                            ))
                        },
                        destroy: i
                    })
                }
                throw new b("Iterable, AsyncIterable or AsyncFunction",r,e)
            }
            if (R(t))
                return e(t.arrayBuffer());
            if (a(t))
                return S(M, t, {
                    objectMode: !0,
                    writable: !1
                });
            if (f(null == t ? void 0 : t.readable) && p(null == t ? void 0 : t.writable))
                return M.fromWeb(t);
            if ("object" == typeof (null == t ? void 0 : t.writable) || "object" == typeof (null == t ? void 0 : t.readable)) {
                return T({
                    readable: null != t && t.readable ? u(null == t ? void 0 : t.readable) ? null == t ? void 0 : t.readable : e(t.readable) : void 0,
                    writable: null != t && t.writable ? l(null == t ? void 0 : t.writable) ? null == t ? void 0 : t.writable : e(t.writable) : void 0
                })
            }
            const s = null == t ? void 0 : t.then;
            if ("function" == typeof s) {
                let e;
                return A(s, t, (t => {
                        null != t && e.push(t),
                            e.push(null)
                    }
                ), (t => {
                        y(e, t)
                    }
                )),
                    e = new M({
                        objectMode: !0,
                        writable: !1,
                        read() {}
                    })
            }
            throw new m(r,["Blob", "ReadableStream", "WritableStream", "Stream", "Iterable", "AsyncIterable", "Function", "{ readable, writable } pair", "Promise"],t)
        }
    }
        , {
            "../../ours/errors": 145,
            "../../ours/primordials": 146,
            "../../ours/util": 147,
            "./destroy": 129,
            "./duplex": 130,
            "./end-of-stream": 132,
            "./from": 133,
            "./readable": 138,
            "./utils": 141,
            "./writable": 142,
            "abort-controller": 192,
            buffer: 195,
            "process/": 211
        }],
    132: [function(e, t, r) {
        const n = e("process/")
            , {AbortError: s, codes: o} = e("../../ours/errors")
            , {ERR_INVALID_ARG_TYPE: i, ERR_STREAM_PREMATURE_CLOSE: a} = o
            , {kEmptyObject: c, once: u} = e("../../ours/util")
            , {validateAbortSignal: l, validateFunction: d, validateObject: f, validateBoolean: p} = e("../validators")
            , {Promise: h, PromisePrototypeThen: g, SymbolDispose: m} = e("../../ours/primordials")
            , {isClosed: b, isReadable: y, isReadableNodeStream: w, isReadableStream: v, isReadableFinished: _, isReadableErrored: E, isWritable: S, isWritableNodeStream: j, isWritableStream: R, isWritableFinished: I, isWritableErrored: A, isNodeStream: M, willEmitClose: T, kIsClosedPromise: C} = e("./utils");
        let O;
        const x = () => {}
        ;
        function N(t, r, o) {
            var p, h;
            if (2 === arguments.length ? (o = r,
                r = c) : null == r ? r = c : f(r, "options"),
                d(o, "callback"),
                l(r.signal, "options.signal"),
                o = u(o),
            v(t) || R(t))
                return function(t, r, o) {
                    let i = !1
                        , a = x;
                    if (r.signal)
                        if (a = () => {
                            i = !0,
                                o.call(t, new s(void 0,{
                                    cause: r.signal.reason
                                }))
                        }
                            ,
                            r.signal.aborted)
                            n.nextTick(a);
                        else {
                            O = O || e("../../ours/util").addAbortListener;
                            const n = O(r.signal, a)
                                , s = o;
                            o = u(( (...e) => {
                                    n[m](),
                                        s.apply(t, e)
                                }
                            ))
                        }
                    const c = (...e) => {
                            i || n.nextTick(( () => o.apply(t, e)))
                        }
                    ;
                    return g(t[C].promise, c, c),
                        x
                }(t, r, o);
            if (!M(t))
                throw new i("stream",["ReadableStream", "WritableStream", "Stream"],t);
            const N = null !== (p = r.readable) && void 0 !== p ? p : w(t)
                , P = null !== (h = r.writable) && void 0 !== h ? h : j(t)
                , k = t._writableState
                , L = t._readableState
                , D = () => {
                    t.writable || U()
                }
            ;
            let B = T(t) && w(t) === N && j(t) === P
                , $ = I(t, !1);
            const U = () => {
                    $ = !0,
                    t.destroyed && (B = !1),
                    (!B || t.readable && !N) && (N && !F || o.call(t))
                }
            ;
            let F = _(t, !1);
            const W = () => {
                    F = !0,
                    t.destroyed && (B = !1),
                    (!B || t.writable && !P) && (P && !$ || o.call(t))
                }
                , z = e => {
                    o.call(t, e)
                }
            ;
            let V = b(t);
            const G = () => {
                    V = !0;
                    const e = A(t) || E(t);
                    return e && "boolean" != typeof e ? o.call(t, e) : N && !F && w(t, !0) && !_(t, !1) ? o.call(t, new a) : !P || $ || I(t, !1) ? void o.call(t) : o.call(t, new a)
                }
                , H = () => {
                    V = !0;
                    const e = A(t) || E(t);
                    if (e && "boolean" != typeof e)
                        return o.call(t, e);
                    o.call(t)
                }
                , J = () => {
                    t.req.on("finish", U)
                }
            ;
            !function(e) {
                return e.setHeader && "function" == typeof e.abort
            }(t) ? P && !k && (t.on("end", D),
                t.on("close", D)) : (t.on("complete", U),
            B || t.on("abort", G),
                t.req ? J() : t.on("request", J)),
            B || "boolean" != typeof t.aborted || t.on("aborted", G),
                t.on("end", W),
                t.on("finish", U),
            !1 !== r.error && t.on("error", z),
                t.on("close", G),
                V ? n.nextTick(G) : null != k && k.errorEmitted || null != L && L.errorEmitted ? B || n.nextTick(H) : (N || B && !y(t) || !$ && !1 !== S(t)) && (P || B && !S(t) || !F && !1 !== y(t)) ? L && t.req && t.aborted && n.nextTick(H) : n.nextTick(H);
            const q = () => {
                    o = x,
                        t.removeListener("aborted", G),
                        t.removeListener("complete", U),
                        t.removeListener("abort", G),
                        t.removeListener("request", J),
                    t.req && t.req.removeListener("finish", U),
                        t.removeListener("end", D),
                        t.removeListener("close", D),
                        t.removeListener("finish", U),
                        t.removeListener("end", W),
                        t.removeListener("error", z),
                        t.removeListener("close", G)
                }
            ;
            if (r.signal && !V) {
                const i = () => {
                        const e = o;
                        q(),
                            e.call(t, new s(void 0,{
                                cause: r.signal.reason
                            }))
                    }
                ;
                if (r.signal.aborted)
                    n.nextTick(i);
                else {
                    O = O || e("../../ours/util").addAbortListener;
                    const n = O(r.signal, i)
                        , s = o;
                    o = u(( (...e) => {
                            n[m](),
                                s.apply(t, e)
                        }
                    ))
                }
            }
            return q
        }
        t.exports = N,
            t.exports.finished = function(e, t) {
                var r;
                let n = !1;
                return null === t && (t = c),
                null !== (r = t) && void 0 !== r && r.cleanup && (p(t.cleanup, "cleanup"),
                    n = t.cleanup),
                    new h(( (r, s) => {
                            const o = N(e, t, (e => {
                                    n && o(),
                                        e ? s(e) : r()
                                }
                            ))
                        }
                    ))
            }
    }
        , {
            "../../ours/errors": 145,
            "../../ours/primordials": 146,
            "../../ours/util": 147,
            "../validators": 143,
            "./utils": 141,
            "process/": 211
        }],
    133: [function(e, t, r) {
        "use strict";
        const n = e("process/")
            , {PromisePrototypeThen: s, SymbolAsyncIterator: o, SymbolIterator: i} = e("../../ours/primordials")
            , {Buffer: a} = e("buffer")
            , {ERR_INVALID_ARG_TYPE: c, ERR_STREAM_NULL_VALUES: u} = e("../../ours/errors").codes;
        t.exports = function(e, t, r) {
            let l, d;
            if ("string" == typeof t || t instanceof a)
                return new e({
                    objectMode: !0,
                    ...r,
                    read() {
                        this.push(t),
                            this.push(null)
                    }
                });
            if (t && t[o])
                d = !0,
                    l = t[o]();
            else {
                if (!t || !t[i])
                    throw new c("iterable",["Iterable"],t);
                d = !1,
                    l = t[i]()
            }
            const f = new e({
                objectMode: !0,
                highWaterMark: 1,
                ...r
            });
            let p = !1;
            return f._read = function() {
                p || (p = !0,
                    async function() {
                        for (; ; ) {
                            try {
                                const {value: e, done: t} = d ? await l.next() : l.next();
                                if (t)
                                    f.push(null);
                                else {
                                    const t = e && "function" == typeof e.then ? await e : e;
                                    if (null === t)
                                        throw p = !1,
                                            new u;
                                    if (f.push(t))
                                        continue;
                                    p = !1
                                }
                            } catch (e) {
                                f.destroy(e)
                            }
                            break
                        }
                    }())
            }
                ,
                f._destroy = function(e, t) {
                    s(async function(e) {
                        const t = null != e
                            , r = "function" == typeof l.throw;
                        if (t && r) {
                            const {value: t, done: r} = await l.throw(e);
                            if (await t,
                                r)
                                return
                        }
                        if ("function" == typeof l.return) {
                            const {value: e} = await l.return();
                            await e
                        }
                    }(e), ( () => n.nextTick(t, e)), (r => n.nextTick(t, r || e)))
                }
                ,
                f
        }
    }
        , {
            "../../ours/errors": 145,
            "../../ours/primordials": 146,
            buffer: 195,
            "process/": 211
        }],
    134: [function(e, t, r) {
        "use strict";
        const {ArrayIsArray: n, ObjectSetPrototypeOf: s} = e("../../ours/primordials")
            , {EventEmitter: o} = e("events");
        function i(e) {
            o.call(this, e)
        }
        function a(e, t, r) {
            if ("function" == typeof e.prependListener)
                return e.prependListener(t, r);
            e._events && e._events[t] ? n(e._events[t]) ? e._events[t].unshift(r) : e._events[t] = [r, e._events[t]] : e.on(t, r)
        }
        s(i.prototype, o.prototype),
            s(i, o),
            i.prototype.pipe = function(e, t) {
                const r = this;
                function n(t) {
                    e.writable && !1 === e.write(t) && r.pause && r.pause()
                }
                function s() {
                    r.readable && r.resume && r.resume()
                }
                r.on("data", n),
                    e.on("drain", s),
                e._isStdio || t && !1 === t.end || (r.on("end", c),
                    r.on("close", u));
                let i = !1;
                function c() {
                    i || (i = !0,
                        e.end())
                }
                function u() {
                    i || (i = !0,
                    "function" == typeof e.destroy && e.destroy())
                }
                function l(e) {
                    d(),
                    0 === o.listenerCount(this, "error") && this.emit("error", e)
                }
                function d() {
                    r.removeListener("data", n),
                        e.removeListener("drain", s),
                        r.removeListener("end", c),
                        r.removeListener("close", u),
                        r.removeListener("error", l),
                        e.removeListener("error", l),
                        r.removeListener("end", d),
                        r.removeListener("close", d),
                        e.removeListener("close", d)
                }
                return a(r, "error", l),
                    a(e, "error", l),
                    r.on("end", d),
                    r.on("close", d),
                    e.on("close", d),
                    e.emit("pipe", r),
                    e
            }
            ,
            t.exports = {
                Stream: i,
                prependListener: a
            }
    }
        , {
            "../../ours/primordials": 146,
            events: 200
        }],
    135: [function(e, t, r) {
        "use strict";
        const n = globalThis.AbortController || e("abort-controller").AbortController
            , {codes: {ERR_INVALID_ARG_VALUE: s, ERR_INVALID_ARG_TYPE: o, ERR_MISSING_ARGS: i, ERR_OUT_OF_RANGE: a}, AbortError: c} = e("../../ours/errors")
            , {validateAbortSignal: u, validateInteger: l, validateObject: d} = e("../validators")
            , f = e("../../ours/primordials").Symbol("kWeak")
            , p = e("../../ours/primordials").Symbol("kResistStopPropagation")
            , {finished: h} = e("./end-of-stream")
            , g = e("./compose")
            , {addAbortSignalNoValidate: m} = e("./add-abort-signal")
            , {isWritable: b, isNodeStream: y} = e("./utils")
            , {deprecate: w} = e("../../ours/util")
            , {ArrayPrototypePush: v, Boolean: _, MathFloor: E, Number: S, NumberIsNaN: j, Promise: R, PromiseReject: I, PromiseResolve: A, PromisePrototypeThen: M, Symbol: T} = e("../../ours/primordials")
            , C = T("kEmpty")
            , O = T("kEof");
        function x(t, r) {
            if ("function" != typeof t)
                throw new o("fn",["Function", "AsyncFunction"],t);
            null != r && d(r, "options"),
            null != (null == r ? void 0 : r.signal) && u(r.signal, "options.signal");
            let n = 1;
            null != (null == r ? void 0 : r.concurrency) && (n = E(r.concurrency));
            let s = n - 1;
            return null != (null == r ? void 0 : r.highWaterMark) && (s = E(r.highWaterMark)),
                l(n, "options.concurrency", 1),
                l(s, "options.highWaterMark", 0),
                s += n,
                async function*() {
                    const o = e("../../ours/util").AbortSignalAny([null == r ? void 0 : r.signal].filter(_))
                        , i = this
                        , a = []
                        , u = {
                        signal: o
                    };
                    let l, d, f = !1, p = 0;
                    function h() {
                        f = !0,
                            g()
                    }
                    function g() {
                        p -= 1,
                            m()
                    }
                    function m() {
                        d && !f && p < n && a.length < s && (d(),
                            d = null)
                    }
                    !async function() {
                        try {
                            for await(let e of i) {
                                if (f)
                                    return;
                                if (o.aborted)
                                    throw new c;
                                try {
                                    if (e = t(e, u),
                                    e === C)
                                        continue;
                                    e = A(e)
                                } catch (t) {
                                    e = I(t)
                                }
                                p += 1,
                                    M(e, g, h),
                                    a.push(e),
                                l && (l(),
                                    l = null),
                                !f && (a.length >= s || p >= n) && await new R((e => {
                                        d = e
                                    }
                                ))
                            }
                            a.push(O)
                        } catch (e) {
                            const t = I(e);
                            M(t, g, h),
                                a.push(t)
                        } finally {
                            f = !0,
                            l && (l(),
                                l = null)
                        }
                    }();
                    try {
                        for (; ; ) {
                            for (; a.length > 0; ) {
                                const e = await a[0];
                                if (e === O)
                                    return;
                                if (o.aborted)
                                    throw new c;
                                e !== C && (yield e),
                                    a.shift(),
                                    m()
                            }
                            await new R((e => {
                                    l = e
                                }
                            ))
                        }
                    } finally {
                        f = !0,
                        d && (d(),
                            d = null)
                    }
                }
                    .call(this)
        }
        async function N(e, t=void 0) {
            for await(const r of P.call(this, e, t))
                return !0;
            return !1
        }
        function P(e, t) {
            if ("function" != typeof e)
                throw new o("fn",["Function", "AsyncFunction"],e);
            return x.call(this, (async function(t, r) {
                    return await e(t, r) ? t : C
                }
            ), t)
        }
        class k extends i {
            constructor() {
                super("reduce"),
                    this.message = "Reduce of an empty stream requires an initial value"
            }
        }
        function L(e) {
            if (e = S(e),
                j(e))
                return 0;
            if (e < 0)
                throw new a("number",">= 0",e);
            return e
        }
        t.exports.streamReturningOperators = {
            asIndexedPairs: w((function(e=void 0) {
                    return null != e && d(e, "options"),
                    null != (null == e ? void 0 : e.signal) && u(e.signal, "options.signal"),
                        async function*() {
                            let t = 0;
                            for await(const n of this) {
                                var r;
                                if (null != e && null !== (r = e.signal) && void 0 !== r && r.aborted)
                                    throw new c({
                                        cause: e.signal.reason
                                    });
                                yield[t++, n]
                            }
                        }
                            .call(this)
                }
            ), "readable.asIndexedPairs will be removed in a future version."),
            drop: function(e, t=void 0) {
                return null != t && d(t, "options"),
                null != (null == t ? void 0 : t.signal) && u(t.signal, "options.signal"),
                    e = L(e),
                    async function*() {
                        var r;
                        if (null != t && null !== (r = t.signal) && void 0 !== r && r.aborted)
                            throw new c;
                        for await(const r of this) {
                            var n;
                            if (null != t && null !== (n = t.signal) && void 0 !== n && n.aborted)
                                throw new c;
                            e-- <= 0 && (yield r)
                        }
                    }
                        .call(this)
            },
            filter: P,
            flatMap: function(e, t) {
                const r = x.call(this, e, t);
                return async function*() {
                    for await(const e of r)
                        yield*e
                }
                    .call(this)
            },
            map: x,
            take: function(e, t=void 0) {
                return null != t && d(t, "options"),
                null != (null == t ? void 0 : t.signal) && u(t.signal, "options.signal"),
                    e = L(e),
                    async function*() {
                        var r;
                        if (null != t && null !== (r = t.signal) && void 0 !== r && r.aborted)
                            throw new c;
                        for await(const r of this) {
                            var n;
                            if (null != t && null !== (n = t.signal) && void 0 !== n && n.aborted)
                                throw new c;
                            if (e-- > 0 && (yield r),
                            e <= 0)
                                return
                        }
                    }
                        .call(this)
            },
            compose: function(e, t) {
                if (null != t && d(t, "options"),
                null != (null == t ? void 0 : t.signal) && u(t.signal, "options.signal"),
                y(e) && !b(e))
                    throw new s("stream",e,"must be writable");
                const r = g(this, e);
                return null != t && t.signal && m(t.signal, r),
                    r
            }
        },
            t.exports.promiseReturningOperators = {
                every: async function(e, t=void 0) {
                    if ("function" != typeof e)
                        throw new o("fn",["Function", "AsyncFunction"],e);
                    return !await N.call(this, (async (...t) => !await e(...t)), t)
                },
                forEach: async function(e, t) {
                    if ("function" != typeof e)
                        throw new o("fn",["Function", "AsyncFunction"],e);
                    for await(const r of x.call(this, (async function(t, r) {
                            return await e(t, r),
                                C
                        }
                    ), t))
                        ;
                },
                reduce: async function(e, t, r) {
                    var s;
                    if ("function" != typeof e)
                        throw new o("reducer",["Function", "AsyncFunction"],e);
                    null != r && d(r, "options"),
                    null != (null == r ? void 0 : r.signal) && u(r.signal, "options.signal");
                    let i = arguments.length > 1;
                    if (null != r && null !== (s = r.signal) && void 0 !== s && s.aborted) {
                        const e = new c(void 0,{
                            cause: r.signal.reason
                        });
                        throw this.once("error", ( () => {}
                        )),
                            await h(this.destroy(e)),
                            e
                    }
                    const a = new n
                        , l = a.signal;
                    if (null != r && r.signal) {
                        const e = {
                            once: !0,
                            [f]: this,
                            [p]: !0
                        };
                        r.signal.addEventListener("abort", ( () => a.abort()), e)
                    }
                    let g = !1;
                    try {
                        for await(const n of this) {
                            var m;
                            if (g = !0,
                            null != r && null !== (m = r.signal) && void 0 !== m && m.aborted)
                                throw new c;
                            i ? t = await e(t, n, {
                                signal: l
                            }) : (t = n,
                                i = !0)
                        }
                        if (!g && !i)
                            throw new k
                    } finally {
                        a.abort()
                    }
                    return t
                },
                toArray: async function(e) {
                    null != e && d(e, "options"),
                    null != (null == e ? void 0 : e.signal) && u(e.signal, "options.signal");
                    const t = [];
                    for await(const n of this) {
                        var r;
                        if (null != e && null !== (r = e.signal) && void 0 !== r && r.aborted)
                            throw new c(void 0,{
                                cause: e.signal.reason
                            });
                        v(t, n)
                    }
                    return t
                },
                some: N,
                find: async function(e, t) {
                    for await(const r of P.call(this, e, t))
                        return r
                }
            }
    }
        , {
            "../../ours/errors": 145,
            "../../ours/primordials": 146,
            "../../ours/util": 147,
            "../validators": 143,
            "./add-abort-signal": 126,
            "./compose": 128,
            "./end-of-stream": 132,
            "./utils": 141,
            "abort-controller": 192
        }],
    136: [function(e, t, r) {
        "use strict";
        const {ObjectSetPrototypeOf: n} = e("../../ours/primordials");
        t.exports = o;
        const s = e("./transform");
        function o(e) {
            if (!(this instanceof o))
                return new o(e);
            s.call(this, e)
        }
        n(o.prototype, s.prototype),
            n(o, s),
            o.prototype._transform = function(e, t, r) {
                r(null, e)
            }
    }
        , {
            "../../ours/primordials": 146,
            "./transform": 140
        }],
    137: [function(e, t, r) {
        const n = e("process/")
            , {ArrayIsArray: s, Promise: o, SymbolAsyncIterator: i, SymbolDispose: a} = e("../../ours/primordials")
            , c = e("./end-of-stream")
            , {once: u} = e("../../ours/util")
            , l = e("./destroy")
            , d = e("./duplex")
            , {aggregateTwoErrors: f, codes: {ERR_INVALID_ARG_TYPE: p, ERR_INVALID_RETURN_VALUE: h, ERR_MISSING_ARGS: g, ERR_STREAM_DESTROYED: m, ERR_STREAM_PREMATURE_CLOSE: b}, AbortError: y} = e("../../ours/errors")
            , {validateFunction: w, validateAbortSignal: v} = e("../validators")
            , {isIterable: _, isReadable: E, isReadableNodeStream: S, isNodeStream: j, isTransformStream: R, isWebStream: I, isReadableStream: A, isReadableFinished: M} = e("./utils")
            , T = globalThis.AbortController || e("abort-controller").AbortController;
        let C, O, x;
        function N(e, t, r) {
            let n = !1;
            e.on("close", ( () => {
                    n = !0
                }
            ));
            return {
                destroy: t => {
                    n || (n = !0,
                        l.destroyer(e, t || new m("pipe")))
                }
                ,
                cleanup: c(e, {
                    readable: t,
                    writable: r
                }, (e => {
                        n = !e
                    }
                ))
            }
        }
        function P(t) {
            if (_(t))
                return t;
            if (S(t))
                return async function*(t) {
                    O || (O = e("./readable"));
                    yield*O.prototype[i].call(t)
                }(t);
            throw new p("val",["Readable", "Iterable", "AsyncIterable"],t)
        }
        async function k(e, t, r, {end: n}) {
            let s, i = null;
            const a = e => {
                if (e && (s = e),
                    i) {
                    const e = i;
                    i = null,
                        e()
                }
            }
                , u = () => new o(( (e, t) => {
                    s ? t(s) : i = () => {
                        s ? t(s) : e()
                    }
                }
            ));
            t.on("drain", a);
            const l = c(t, {
                readable: !1
            }, a);
            try {
                t.writableNeedDrain && await u();
                for await(const r of e)
                    t.write(r) || await u();
                n && (t.end(),
                    await u()),
                    r()
            } catch (e) {
                r(s !== e ? f(s, e) : e)
            } finally {
                l(),
                    t.off("drain", a)
            }
        }
        async function L(e, t, r, {end: n}) {
            R(t) && (t = t.writable);
            const s = t.getWriter();
            try {
                for await(const t of e)
                    await s.ready,
                        s.write(t).catch(( () => {}
                        ));
                await s.ready,
                n && await s.close(),
                    r()
            } catch (e) {
                try {
                    await s.abort(e),
                        r(e)
                } catch (e) {
                    r(e)
                }
            }
        }
        function D(t, r, o) {
            if (1 === t.length && s(t[0]) && (t = t[0]),
            t.length < 2)
                throw new g("streams");
            const i = new T
                , c = i.signal
                , u = null == o ? void 0 : o.signal
                , l = [];
            function f() {
                U(new y)
            }
            let m, b, w;
            v(u, "options.signal"),
                x = x || e("../../ours/util").addAbortListener,
            u && (m = x(u, f));
            const M = [];
            let O, D = 0;
            function $(e) {
                U(e, 0 == --D)
            }
            function U(e, t) {
                var s;
                if (!e || b && "ERR_STREAM_PREMATURE_CLOSE" !== b.code || (b = e),
                b || t) {
                    for (; M.length; )
                        M.shift()(b);
                    null === (s = m) || void 0 === s || s[a](),
                        i.abort(),
                    t && (b || l.forEach((e => e())),
                        n.nextTick(r, b, w))
                }
            }
            for (let V = 0; V < t.length; V++) {
                const G = t[V]
                    , H = V < t.length - 1
                    , J = V > 0
                    , q = H || !1 !== (null == o ? void 0 : o.end)
                    , X = V === t.length - 1;
                if (j(G)) {
                    if (q) {
                        const {destroy: Y, cleanup: Z} = N(G, H, J);
                        M.push(Y),
                        E(G) && X && l.push(Z)
                    }
                    function F(e) {
                        e && "AbortError" !== e.name && "ERR_STREAM_PREMATURE_CLOSE" !== e.code && $(e)
                    }
                    G.on("error", F),
                    E(G) && X && l.push(( () => {
                            G.removeListener("error", F)
                        }
                    ))
                }
                if (0 === V)
                    if ("function" == typeof G) {
                        if (O = G({
                            signal: c
                        }),
                            !_(O))
                            throw new h("Iterable, AsyncIterable or Stream","source",O)
                    } else
                        O = _(G) || S(G) || R(G) ? G : d.from(G);
                else if ("function" == typeof G) {
                    var W;
                    if (R(O))
                        O = P(null === (W = O) || void 0 === W ? void 0 : W.readable);
                    else
                        O = P(O);
                    if (O = G(O, {
                        signal: c
                    }),
                        H) {
                        if (!_(O, !0))
                            throw new h("AsyncIterable",`transform[${V - 1}]`,O)
                    } else {
                        var z;
                        C || (C = e("./passthrough"));
                        const K = new C({
                            objectMode: !0
                        })
                            , Q = null === (z = O) || void 0 === z ? void 0 : z.then;
                        if ("function" == typeof Q)
                            D++,
                                Q.call(O, (e => {
                                        w = e,
                                        null != e && K.write(e),
                                        q && K.end(),
                                            n.nextTick($)
                                    }
                                ), (e => {
                                        K.destroy(e),
                                            n.nextTick($, e)
                                    }
                                ));
                        else if (_(O, !0))
                            D++,
                                k(O, K, $, {
                                    end: q
                                });
                        else {
                            if (!A(O) && !R(O))
                                throw new h("AsyncIterable or Promise","destination",O);
                            {
                                const re = O.readable || O;
                                D++,
                                    k(re, K, $, {
                                        end: q
                                    })
                            }
                        }
                        O = K;
                        const {destroy: ee, cleanup: te} = N(O, !1, !0);
                        M.push(ee),
                        X && l.push(te)
                    }
                } else if (j(G)) {
                    if (S(O)) {
                        D += 2;
                        const ne = B(O, G, $, {
                            end: q
                        });
                        E(G) && X && l.push(ne)
                    } else if (R(O) || A(O)) {
                        const se = O.readable || O;
                        D++,
                            k(se, G, $, {
                                end: q
                            })
                    } else {
                        if (!_(O))
                            throw new p("val",["Readable", "Iterable", "AsyncIterable", "ReadableStream", "TransformStream"],O);
                        D++,
                            k(O, G, $, {
                                end: q
                            })
                    }
                    O = G
                } else if (I(G)) {
                    if (S(O))
                        D++,
                            L(P(O), G, $, {
                                end: q
                            });
                    else if (A(O) || _(O))
                        D++,
                            L(O, G, $, {
                                end: q
                            });
                    else {
                        if (!R(O))
                            throw new p("val",["Readable", "Iterable", "AsyncIterable", "ReadableStream", "TransformStream"],O);
                        D++,
                            L(O.readable, G, $, {
                                end: q
                            })
                    }
                    O = G
                } else
                    O = d.from(G)
            }
            return (null != c && c.aborted || null != u && u.aborted) && n.nextTick(f),
                O
        }
        function B(e, t, r, {end: s}) {
            let o = !1;
            if (t.on("close", ( () => {
                    o || r(new b)
                }
            )),
                e.pipe(t, {
                    end: !1
                }),
                s) {
                function i() {
                    o = !0,
                        t.end()
                }
                M(e) ? n.nextTick(i) : e.once("end", i)
            } else
                r();
            return c(e, {
                readable: !0,
                writable: !1
            }, (t => {
                    const n = e._readableState;
                    t && "ERR_STREAM_PREMATURE_CLOSE" === t.code && n && n.ended && !n.errored && !n.errorEmitted ? e.once("end", r).once("error", r) : r(t)
                }
            )),
                c(t, {
                    readable: !1,
                    writable: !0
                }, r)
        }
        t.exports = {
            pipelineImpl: D,
            pipeline: function(...e) {
                return D(e, u(function(e) {
                    return w(e[e.length - 1], "streams[stream.length - 1]"),
                        e.pop()
                }(e)))
            }
        }
    }
        , {
            "../../ours/errors": 145,
            "../../ours/primordials": 146,
            "../../ours/util": 147,
            "../validators": 143,
            "./destroy": 129,
            "./duplex": 130,
            "./end-of-stream": 132,
            "./passthrough": 136,
            "./readable": 138,
            "./utils": 141,
            "abort-controller": 192,
            "process/": 211
        }],
    138: [function(e, t, r) {
        const n = e("process/")
            , {ArrayPrototypeIndexOf: s, NumberIsInteger: o, NumberIsNaN: i, NumberParseInt: a, ObjectDefineProperties: c, ObjectKeys: u, ObjectSetPrototypeOf: l, Promise: d, SafeSet: f, SymbolAsyncDispose: p, SymbolAsyncIterator: h, Symbol: g} = e("../../ours/primordials");
        t.exports = X,
            X.ReadableState = q;
        const {EventEmitter: m} = e("events")
            , {Stream: b, prependListener: y} = e("./legacy")
            , {Buffer: w} = e("buffer")
            , {addAbortSignal: v} = e("./add-abort-signal")
            , _ = e("./end-of-stream");
        let E = e("../../ours/util").debuglog("stream", (e => {
                E = e
            }
        ));
        const S = e("./buffer_list")
            , j = e("./destroy")
            , {getHighWaterMark: R, getDefaultHighWaterMark: I} = e("./state")
            , {aggregateTwoErrors: A, codes: {ERR_INVALID_ARG_TYPE: M, ERR_METHOD_NOT_IMPLEMENTED: T, ERR_OUT_OF_RANGE: C, ERR_STREAM_PUSH_AFTER_EOF: O, ERR_STREAM_UNSHIFT_AFTER_END_EVENT: x}, AbortError: N} = e("../../ours/errors")
            , {validateObject: P} = e("../validators")
            , k = g("kPaused")
            , {StringDecoder: L} = e("string_decoder")
            , D = e("./from");
        l(X.prototype, b.prototype),
            l(X, b);
        const B = () => {}
            , {errorOrDestroy: $} = j
            , U = 1
            , F = 16
            , W = 32
            , z = 64
            , V = 2048
            , G = 4096
            , H = 65536;
        function J(e) {
            return {
                enumerable: !1,
                get() {
                    return !!(this.state & e)
                },
                set(t) {
                    t ? this.state |= e : this.state &= ~e
                }
            }
        }
        function q(t, r, n) {
            "boolean" != typeof n && (n = r instanceof e("./duplex")),
                this.state = V | G | F | W,
            t && t.objectMode && (this.state |= U),
            n && t && t.readableObjectMode && (this.state |= U),
                this.highWaterMark = t ? R(this, t, "readableHighWaterMark", n) : I(!1),
                this.buffer = new S,
                this.length = 0,
                this.pipes = [],
                this.flowing = null,
                this[k] = null,
            t && !1 === t.emitClose && (this.state &= ~V),
            t && !1 === t.autoDestroy && (this.state &= ~G),
                this.errored = null,
                this.defaultEncoding = t && t.defaultEncoding || "utf8",
                this.awaitDrainWriters = null,
                this.decoder = null,
                this.encoding = null,
            t && t.encoding && (this.decoder = new L(t.encoding),
                this.encoding = t.encoding)
        }
        function X(t) {
            if (!(this instanceof X))
                return new X(t);
            const r = this instanceof e("./duplex");
            this._readableState = new q(t,this,r),
            t && ("function" == typeof t.read && (this._read = t.read),
            "function" == typeof t.destroy && (this._destroy = t.destroy),
            "function" == typeof t.construct && (this._construct = t.construct),
            t.signal && !r && v(t.signal, this)),
                b.call(this, t),
                j.construct(this, ( () => {
                        this._readableState.needReadable && te(this, this._readableState)
                    }
                ))
        }
        function Y(e, t, r, n) {
            E("readableAddChunk", t);
            const s = e._readableState;
            let o;
            if (s.state & U || ("string" == typeof t ? (r = r || s.defaultEncoding,
            s.encoding !== r && (n && s.encoding ? t = w.from(t, r).toString(s.encoding) : (t = w.from(t, r),
                r = ""))) : t instanceof w ? r = "" : b._isUint8Array(t) ? (t = b._uint8ArrayToBuffer(t),
                r = "") : null != t && (o = new M("chunk",["string", "Buffer", "Uint8Array"],t))),
                o)
                $(e, o);
            else if (null === t)
                s.state &= -9,
                    function(e, t) {
                        if (E("onEofChunk"),
                            t.ended)
                            return;
                        if (t.decoder) {
                            const e = t.decoder.end();
                            e && e.length && (t.buffer.push(e),
                                t.length += t.objectMode ? 1 : e.length)
                        }
                        t.ended = !0,
                            t.sync ? Q(e) : (t.needReadable = !1,
                                t.emittedReadable = !0,
                                ee(e))
                    }(e, s);
            else if (s.state & U || t && t.length > 0)
                if (n)
                    if (4 & s.state)
                        $(e, new x);
                    else {
                        if (s.destroyed || s.errored)
                            return !1;
                        Z(e, s, t, !0)
                    }
                else if (s.ended)
                    $(e, new O);
                else {
                    if (s.destroyed || s.errored)
                        return !1;
                    s.state &= -9,
                        s.decoder && !r ? (t = s.decoder.write(t),
                            s.objectMode || 0 !== t.length ? Z(e, s, t, !1) : te(e, s)) : Z(e, s, t, !1)
                }
            else
                n || (s.state &= -9,
                    te(e, s));
            return !s.ended && (s.length < s.highWaterMark || 0 === s.length)
        }
        function Z(e, t, r, n) {
            t.flowing && 0 === t.length && !t.sync && e.listenerCount("data") > 0 ? (t.state & H ? t.awaitDrainWriters.clear() : t.awaitDrainWriters = null,
                t.dataEmitted = !0,
                e.emit("data", r)) : (t.length += t.objectMode ? 1 : r.length,
                n ? t.buffer.unshift(r) : t.buffer.push(r),
            t.state & z && Q(e)),
                te(e, t)
        }
        c(q.prototype, {
            objectMode: J(U),
            ended: J(2),
            endEmitted: J(4),
            reading: J(8),
            constructed: J(F),
            sync: J(W),
            needReadable: J(z),
            emittedReadable: J(128),
            readableListening: J(256),
            resumeScheduled: J(512),
            errorEmitted: J(1024),
            emitClose: J(V),
            autoDestroy: J(G),
            destroyed: J(8192),
            closed: J(16384),
            closeEmitted: J(32768),
            multiAwaitDrain: J(H),
            readingMore: J(1 << 17),
            dataEmitted: J(1 << 18)
        }),
            X.prototype.destroy = j.destroy,
            X.prototype._undestroy = j.undestroy,
            X.prototype._destroy = function(e, t) {
                t(e)
            }
            ,
            X.prototype[m.captureRejectionSymbol] = function(e) {
                this.destroy(e)
            }
            ,
            X.prototype[p] = function() {
                let e;
                return this.destroyed || (e = this.readableEnded ? null : new N,
                    this.destroy(e)),
                    new d(( (t, r) => _(this, (n => n && n !== e ? r(n) : t(null)))))
            }
            ,
            X.prototype.push = function(e, t) {
                return Y(this, e, t, !1)
            }
            ,
            X.prototype.unshift = function(e, t) {
                return Y(this, e, t, !0)
            }
            ,
            X.prototype.isPaused = function() {
                const e = this._readableState;
                return !0 === e[k] || !1 === e.flowing
            }
            ,
            X.prototype.setEncoding = function(e) {
                const t = new L(e);
                this._readableState.decoder = t,
                    this._readableState.encoding = this._readableState.decoder.encoding;
                const r = this._readableState.buffer;
                let n = "";
                for (const e of r)
                    n += t.write(e);
                return r.clear(),
                "" !== n && r.push(n),
                    this._readableState.length = n.length,
                    this
            }
        ;
        function K(e, t) {
            return e <= 0 || 0 === t.length && t.ended ? 0 : t.state & U ? 1 : i(e) ? t.flowing && t.length ? t.buffer.first().length : t.length : e <= t.length ? e : t.ended ? t.length : 0
        }
        function Q(e) {
            const t = e._readableState;
            E("emitReadable", t.needReadable, t.emittedReadable),
                t.needReadable = !1,
            t.emittedReadable || (E("emitReadable", t.flowing),
                t.emittedReadable = !0,
                n.nextTick(ee, e))
        }
        function ee(e) {
            const t = e._readableState;
            E("emitReadable_", t.destroyed, t.length, t.ended),
            t.destroyed || t.errored || !t.length && !t.ended || (e.emit("readable"),
                t.emittedReadable = !1),
                t.needReadable = !t.flowing && !t.ended && t.length <= t.highWaterMark,
                ie(e)
        }
        function te(e, t) {
            !t.readingMore && t.constructed && (t.readingMore = !0,
                n.nextTick(re, e, t))
        }
        function re(e, t) {
            for (; !t.reading && !t.ended && (t.length < t.highWaterMark || t.flowing && 0 === t.length); ) {
                const r = t.length;
                if (E("maybeReadMore read 0"),
                    e.read(0),
                r === t.length)
                    break
            }
            t.readingMore = !1
        }
        function ne(e) {
            const t = e._readableState;
            t.readableListening = e.listenerCount("readable") > 0,
                t.resumeScheduled && !1 === t[k] ? t.flowing = !0 : e.listenerCount("data") > 0 ? e.resume() : t.readableListening || (t.flowing = null)
        }
        function se(e) {
            E("readable nexttick read 0"),
                e.read(0)
        }
        function oe(e, t) {
            E("resume", t.reading),
            t.reading || e.read(0),
                t.resumeScheduled = !1,
                e.emit("resume"),
                ie(e),
            t.flowing && !t.reading && e.read(0)
        }
        function ie(e) {
            const t = e._readableState;
            for (E("flow", t.flowing); t.flowing && null !== e.read(); )
                ;
        }
        function ae(e, t) {
            "function" != typeof e.read && (e = X.wrap(e, {
                objectMode: !0
            }));
            const r = async function*(e, t) {
                let r, n = B;
                function s(t) {
                    this === e ? (n(),
                        n = B) : n = t
                }
                e.on("readable", s);
                const o = _(e, {
                    writable: !1
                }, (e => {
                        r = e ? A(r, e) : null,
                            n(),
                            n = B
                    }
                ));
                try {
                    for (; ; ) {
                        const t = e.destroyed ? null : e.read();
                        if (null !== t)
                            yield t;
                        else {
                            if (r)
                                throw r;
                            if (null === r)
                                return;
                            await new d(s)
                        }
                    }
                } catch (e) {
                    throw r = A(r, e),
                        r
                } finally {
                    !r && !1 === (null == t ? void 0 : t.destroyOnReturn) || void 0 !== r && !e._readableState.autoDestroy ? (e.off("readable", s),
                        o()) : j.destroyer(e, null)
                }
            }(e, t);
            return r.stream = e,
                r
        }
        function ce(e, t) {
            if (0 === t.length)
                return null;
            let r;
            return t.objectMode ? r = t.buffer.shift() : !e || e >= t.length ? (r = t.decoder ? t.buffer.join("") : 1 === t.buffer.length ? t.buffer.first() : t.buffer.concat(t.length),
                t.buffer.clear()) : r = t.buffer.consume(e, t.decoder),
                r
        }
        function ue(e) {
            const t = e._readableState;
            E("endReadable", t.endEmitted),
            t.endEmitted || (t.ended = !0,
                n.nextTick(le, t, e))
        }
        function le(e, t) {
            if (E("endReadableNT", e.endEmitted, e.length),
            !e.errored && !e.closeEmitted && !e.endEmitted && 0 === e.length)
                if (e.endEmitted = !0,
                    t.emit("end"),
                t.writable && !1 === t.allowHalfOpen)
                    n.nextTick(de, t);
                else if (e.autoDestroy) {
                    const e = t._writableState;
                    (!e || e.autoDestroy && (e.finished || !1 === e.writable)) && t.destroy()
                }
        }
        function de(e) {
            e.writable && !e.writableEnded && !e.destroyed && e.end()
        }
        let fe;
        function pe() {
            return void 0 === fe && (fe = {}),
                fe
        }
        X.prototype.read = function(e) {
            E("read", e),
                void 0 === e ? e = NaN : o(e) || (e = a(e, 10));
            const t = this._readableState
                , r = e;
            if (e > t.highWaterMark && (t.highWaterMark = function(e) {
                if (e > 1073741824)
                    throw new C("size","<= 1GiB",e);
                return e--,
                    e |= e >>> 1,
                    e |= e >>> 2,
                    e |= e >>> 4,
                    e |= e >>> 8,
                    e |= e >>> 16,
                    ++e
            }(e)),
            0 !== e && (t.state &= -129),
            0 === e && t.needReadable && ((0 !== t.highWaterMark ? t.length >= t.highWaterMark : t.length > 0) || t.ended))
                return E("read: emitReadable", t.length, t.ended),
                    0 === t.length && t.ended ? ue(this) : Q(this),
                    null;
            if (0 === (e = K(e, t)) && t.ended)
                return 0 === t.length && ue(this),
                    null;
            let n, s = !!(t.state & z);
            if (E("need readable", s),
            (0 === t.length || t.length - e < t.highWaterMark) && (s = !0,
                E("length less than watermark", s)),
            t.ended || t.reading || t.destroyed || t.errored || !t.constructed)
                s = !1,
                    E("reading, ended or constructing", s);
            else if (s) {
                E("do read"),
                    t.state |= 8 | W,
                0 === t.length && (t.state |= z);
                try {
                    this._read(t.highWaterMark)
                } catch (e) {
                    $(this, e)
                }
                t.state &= ~W,
                t.reading || (e = K(r, t))
            }
            return n = e > 0 ? ce(e, t) : null,
                null === n ? (t.needReadable = t.length <= t.highWaterMark,
                    e = 0) : (t.length -= e,
                    t.multiAwaitDrain ? t.awaitDrainWriters.clear() : t.awaitDrainWriters = null),
            0 === t.length && (t.ended || (t.needReadable = !0),
            r !== e && t.ended && ue(this)),
            null === n || t.errorEmitted || t.closeEmitted || (t.dataEmitted = !0,
                this.emit("data", n)),
                n
        }
            ,
            X.prototype._read = function(e) {
                throw new T("_read()")
            }
            ,
            X.prototype.pipe = function(e, t) {
                const r = this
                    , s = this._readableState;
                1 === s.pipes.length && (s.multiAwaitDrain || (s.multiAwaitDrain = !0,
                    s.awaitDrainWriters = new f(s.awaitDrainWriters ? [s.awaitDrainWriters] : []))),
                    s.pipes.push(e),
                    E("pipe count=%d opts=%j", s.pipes.length, t);
                const o = (!t || !1 !== t.end) && e !== n.stdout && e !== n.stderr ? a : m;
                function i(t, n) {
                    E("onunpipe"),
                    t === r && n && !1 === n.hasUnpiped && (n.hasUnpiped = !0,
                        function() {
                            E("cleanup"),
                                e.removeListener("close", h),
                                e.removeListener("finish", g),
                            c && e.removeListener("drain", c);
                            e.removeListener("error", p),
                                e.removeListener("unpipe", i),
                                r.removeListener("end", a),
                                r.removeListener("end", m),
                                r.removeListener("data", d),
                                u = !0,
                            c && s.awaitDrainWriters && (!e._writableState || e._writableState.needDrain) && c()
                        }())
                }
                function a() {
                    E("onend"),
                        e.end()
                }
                let c;
                s.endEmitted ? n.nextTick(o) : r.once("end", o),
                    e.on("unpipe", i);
                let u = !1;
                function l() {
                    u || (1 === s.pipes.length && s.pipes[0] === e ? (E("false write response, pause", 0),
                        s.awaitDrainWriters = e,
                        s.multiAwaitDrain = !1) : s.pipes.length > 1 && s.pipes.includes(e) && (E("false write response, pause", s.awaitDrainWriters.size),
                        s.awaitDrainWriters.add(e)),
                        r.pause()),
                    c || (c = function(e, t) {
                        return function() {
                            const r = e._readableState;
                            r.awaitDrainWriters === t ? (E("pipeOnDrain", 1),
                                r.awaitDrainWriters = null) : r.multiAwaitDrain && (E("pipeOnDrain", r.awaitDrainWriters.size),
                                r.awaitDrainWriters.delete(t)),
                            r.awaitDrainWriters && 0 !== r.awaitDrainWriters.size || !e.listenerCount("data") || e.resume()
                        }
                    }(r, e),
                        e.on("drain", c))
                }
                function d(t) {
                    E("ondata");
                    const r = e.write(t);
                    E("dest.write", r),
                    !1 === r && l()
                }
                function p(t) {
                    if (E("onerror", t),
                        m(),
                        e.removeListener("error", p),
                    0 === e.listenerCount("error")) {
                        const r = e._writableState || e._readableState;
                        r && !r.errorEmitted ? $(e, t) : e.emit("error", t)
                    }
                }
                function h() {
                    e.removeListener("finish", g),
                        m()
                }
                function g() {
                    E("onfinish"),
                        e.removeListener("close", h),
                        m()
                }
                function m() {
                    E("unpipe"),
                        r.unpipe(e)
                }
                return r.on("data", d),
                    y(e, "error", p),
                    e.once("close", h),
                    e.once("finish", g),
                    e.emit("pipe", r),
                    !0 === e.writableNeedDrain ? l() : s.flowing || (E("pipe resume"),
                        r.resume()),
                    e
            }
            ,
            X.prototype.unpipe = function(e) {
                const t = this._readableState;
                if (0 === t.pipes.length)
                    return this;
                if (!e) {
                    const e = t.pipes;
                    t.pipes = [],
                        this.pause();
                    for (let t = 0; t < e.length; t++)
                        e[t].emit("unpipe", this, {
                            hasUnpiped: !1
                        });
                    return this
                }
                const r = s(t.pipes, e);
                return -1 === r || (t.pipes.splice(r, 1),
                0 === t.pipes.length && this.pause(),
                    e.emit("unpipe", this, {
                        hasUnpiped: !1
                    })),
                    this
            }
            ,
            X.prototype.on = function(e, t) {
                const r = b.prototype.on.call(this, e, t)
                    , s = this._readableState;
                return "data" === e ? (s.readableListening = this.listenerCount("readable") > 0,
                !1 !== s.flowing && this.resume()) : "readable" === e && (s.endEmitted || s.readableListening || (s.readableListening = s.needReadable = !0,
                    s.flowing = !1,
                    s.emittedReadable = !1,
                    E("on readable", s.length, s.reading),
                    s.length ? Q(this) : s.reading || n.nextTick(se, this))),
                    r
            }
            ,
            X.prototype.addListener = X.prototype.on,
            X.prototype.removeListener = function(e, t) {
                const r = b.prototype.removeListener.call(this, e, t);
                return "readable" === e && n.nextTick(ne, this),
                    r
            }
            ,
            X.prototype.off = X.prototype.removeListener,
            X.prototype.removeAllListeners = function(e) {
                const t = b.prototype.removeAllListeners.apply(this, arguments);
                return "readable" !== e && void 0 !== e || n.nextTick(ne, this),
                    t
            }
            ,
            X.prototype.resume = function() {
                const e = this._readableState;
                return e.flowing || (E("resume"),
                    e.flowing = !e.readableListening,
                    function(e, t) {
                        t.resumeScheduled || (t.resumeScheduled = !0,
                            n.nextTick(oe, e, t))
                    }(this, e)),
                    e[k] = !1,
                    this
            }
            ,
            X.prototype.pause = function() {
                return E("call pause flowing=%j", this._readableState.flowing),
                !1 !== this._readableState.flowing && (E("pause"),
                    this._readableState.flowing = !1,
                    this.emit("pause")),
                    this._readableState[k] = !0,
                    this
            }
            ,
            X.prototype.wrap = function(e) {
                let t = !1;
                e.on("data", (r => {
                        !this.push(r) && e.pause && (t = !0,
                            e.pause())
                    }
                )),
                    e.on("end", ( () => {
                            this.push(null)
                        }
                    )),
                    e.on("error", (e => {
                            $(this, e)
                        }
                    )),
                    e.on("close", ( () => {
                            this.destroy()
                        }
                    )),
                    e.on("destroy", ( () => {
                            this.destroy()
                        }
                    )),
                    this._read = () => {
                        t && e.resume && (t = !1,
                            e.resume())
                    }
                ;
                const r = u(e);
                for (let t = 1; t < r.length; t++) {
                    const n = r[t];
                    void 0 === this[n] && "function" == typeof e[n] && (this[n] = e[n].bind(e))
                }
                return this
            }
            ,
            X.prototype[h] = function() {
                return ae(this)
            }
            ,
            X.prototype.iterator = function(e) {
                return void 0 !== e && P(e, "options"),
                    ae(this, e)
            }
            ,
            c(X.prototype, {
                readable: {
                    __proto__: null,
                    get() {
                        const e = this._readableState;
                        return !(!e || !1 === e.readable || e.destroyed || e.errorEmitted || e.endEmitted)
                    },
                    set(e) {
                        this._readableState && (this._readableState.readable = !!e)
                    }
                },
                readableDidRead: {
                    __proto__: null,
                    enumerable: !1,
                    get: function() {
                        return this._readableState.dataEmitted
                    }
                },
                readableAborted: {
                    __proto__: null,
                    enumerable: !1,
                    get: function() {
                        return !(!1 === this._readableState.readable || !this._readableState.destroyed && !this._readableState.errored || this._readableState.endEmitted)
                    }
                },
                readableHighWaterMark: {
                    __proto__: null,
                    enumerable: !1,
                    get: function() {
                        return this._readableState.highWaterMark
                    }
                },
                readableBuffer: {
                    __proto__: null,
                    enumerable: !1,
                    get: function() {
                        return this._readableState && this._readableState.buffer
                    }
                },
                readableFlowing: {
                    __proto__: null,
                    enumerable: !1,
                    get: function() {
                        return this._readableState.flowing
                    },
                    set: function(e) {
                        this._readableState && (this._readableState.flowing = e)
                    }
                },
                readableLength: {
                    __proto__: null,
                    enumerable: !1,
                    get() {
                        return this._readableState.length
                    }
                },
                readableObjectMode: {
                    __proto__: null,
                    enumerable: !1,
                    get() {
                        return !!this._readableState && this._readableState.objectMode
                    }
                },
                readableEncoding: {
                    __proto__: null,
                    enumerable: !1,
                    get() {
                        return this._readableState ? this._readableState.encoding : null
                    }
                },
                errored: {
                    __proto__: null,
                    enumerable: !1,
                    get() {
                        return this._readableState ? this._readableState.errored : null
                    }
                },
                closed: {
                    __proto__: null,
                    get() {
                        return !!this._readableState && this._readableState.closed
                    }
                },
                destroyed: {
                    __proto__: null,
                    enumerable: !1,
                    get() {
                        return !!this._readableState && this._readableState.destroyed
                    },
                    set(e) {
                        this._readableState && (this._readableState.destroyed = e)
                    }
                },
                readableEnded: {
                    __proto__: null,
                    enumerable: !1,
                    get() {
                        return !!this._readableState && this._readableState.endEmitted
                    }
                }
            }),
            c(q.prototype, {
                pipesCount: {
                    __proto__: null,
                    get() {
                        return this.pipes.length
                    }
                },
                paused: {
                    __proto__: null,
                    get() {
                        return !1 !== this[k]
                    },
                    set(e) {
                        this[k] = !!e
                    }
                }
            }),
            X._fromList = ce,
            X.from = function(e, t) {
                return D(X, e, t)
            }
            ,
            X.fromWeb = function(e, t) {
                return pe().newStreamReadableFromReadableStream(e, t)
            }
            ,
            X.toWeb = function(e, t) {
                return pe().newReadableStreamFromStreamReadable(e, t)
            }
            ,
            X.wrap = function(e, t) {
                var r, n;
                return new X({
                    objectMode: null === (r = null !== (n = e.readableObjectMode) && void 0 !== n ? n : e.objectMode) || void 0 === r || r,
                    ...t,
                    destroy(t, r) {
                        j.destroyer(e, t),
                            r(t)
                    }
                }).wrap(e)
            }
    }
        , {
            "../../ours/errors": 145,
            "../../ours/primordials": 146,
            "../../ours/util": 147,
            "../validators": 143,
            "./add-abort-signal": 126,
            "./buffer_list": 127,
            "./destroy": 129,
            "./duplex": 130,
            "./end-of-stream": 132,
            "./from": 133,
            "./legacy": 134,
            "./state": 139,
            buffer: 195,
            events: 200,
            "process/": 211,
            string_decoder: 273
        }],
    139: [function(e, t, r) {
        "use strict";
        const {MathFloor: n, NumberIsInteger: s} = e("../../ours/primordials")
            , {validateInteger: o} = e("../validators")
            , {ERR_INVALID_ARG_VALUE: i} = e("../../ours/errors").codes;
        let a = 16384
            , c = 16;
        function u(e) {
            return e ? c : a
        }
        t.exports = {
            getHighWaterMark: function(e, t, r, o) {
                const a = function(e, t, r) {
                    return null != e.highWaterMark ? e.highWaterMark : t ? e[r] : null
                }(t, o, r);
                if (null != a) {
                    if (!s(a) || a < 0) {
                        throw new i(o ? `options.${r}` : "options.highWaterMark",a)
                    }
                    return n(a)
                }
                return u(e.objectMode)
            },
            getDefaultHighWaterMark: u,
            setDefaultHighWaterMark: function(e, t) {
                o(t, "value", 0),
                    e ? c = t : a = t
            }
        }
    }
        , {
            "../../ours/errors": 145,
            "../../ours/primordials": 146,
            "../validators": 143
        }],
    140: [function(e, t, r) {
        "use strict";
        const {ObjectSetPrototypeOf: n, Symbol: s} = e("../../ours/primordials");
        t.exports = u;
        const {ERR_METHOD_NOT_IMPLEMENTED: o} = e("../../ours/errors").codes
            , i = e("./duplex")
            , {getHighWaterMark: a} = e("./state");
        n(u.prototype, i.prototype),
            n(u, i);
        const c = s("kCallback");
        function u(e) {
            if (!(this instanceof u))
                return new u(e);
            const t = e ? a(this, e, "readableHighWaterMark", !0) : null;
            0 === t && (e = {
                ...e,
                highWaterMark: null,
                readableHighWaterMark: t,
                writableHighWaterMark: e.writableHighWaterMark || 0
            }),
                i.call(this, e),
                this._readableState.sync = !1,
                this[c] = null,
            e && ("function" == typeof e.transform && (this._transform = e.transform),
            "function" == typeof e.flush && (this._flush = e.flush)),
                this.on("prefinish", d)
        }
        function l(e) {
            "function" != typeof this._flush || this.destroyed ? (this.push(null),
            e && e()) : this._flush(( (t, r) => {
                    t ? e ? e(t) : this.destroy(t) : (null != r && this.push(r),
                        this.push(null),
                    e && e())
                }
            ))
        }
        function d() {
            this._final !== l && l.call(this)
        }
        u.prototype._final = l,
            u.prototype._transform = function(e, t, r) {
                throw new o("_transform()")
            }
            ,
            u.prototype._write = function(e, t, r) {
                const n = this._readableState
                    , s = this._writableState
                    , o = n.length;
                this._transform(e, t, ( (e, t) => {
                        e ? r(e) : (null != t && this.push(t),
                            s.ended || o === n.length || n.length < n.highWaterMark ? r() : this[c] = r)
                    }
                ))
            }
            ,
            u.prototype._read = function() {
                if (this[c]) {
                    const e = this[c];
                    this[c] = null,
                        e()
                }
            }
    }
        , {
            "../../ours/errors": 145,
            "../../ours/primordials": 146,
            "./duplex": 130,
            "./state": 139
        }],
    141: [function(e, t, r) {
        "use strict";
        const {SymbolAsyncIterator: n, SymbolIterator: s, SymbolFor: o} = e("../../ours/primordials")
            , i = o("nodejs.stream.destroyed")
            , a = o("nodejs.stream.errored")
            , c = o("nodejs.stream.readable")
            , u = o("nodejs.stream.writable")
            , l = o("nodejs.stream.disturbed")
            , d = o("nodejs.webstream.isClosedPromise")
            , f = o("nodejs.webstream.controllerErrorFunction");
        function p(e, t=!1) {
            var r;
            return !(!e || "function" != typeof e.pipe || "function" != typeof e.on || t && ("function" != typeof e.pause || "function" != typeof e.resume) || e._writableState && !1 === (null === (r = e._readableState) || void 0 === r ? void 0 : r.readable) || e._writableState && !e._readableState)
        }
        function h(e) {
            var t;
            return !(!e || "function" != typeof e.write || "function" != typeof e.on || e._readableState && !1 === (null === (t = e._writableState) || void 0 === t ? void 0 : t.writable))
        }
        function g(e) {
            return e && (e._readableState || e._writableState || "function" == typeof e.write && "function" == typeof e.on || "function" == typeof e.pipe && "function" == typeof e.on)
        }
        function m(e) {
            return !(!e || g(e) || "function" != typeof e.pipeThrough || "function" != typeof e.getReader || "function" != typeof e.cancel)
        }
        function b(e) {
            return !(!e || g(e) || "function" != typeof e.getWriter || "function" != typeof e.abort)
        }
        function y(e) {
            return !(!e || g(e) || "object" != typeof e.readable || "object" != typeof e.writable)
        }
        function w(e) {
            if (!g(e))
                return null;
            const t = e._writableState
                , r = e._readableState
                , n = t || r;
            return !!(e.destroyed || e[i] || null != n && n.destroyed)
        }
        function v(e) {
            if (!h(e))
                return null;
            if (!0 === e.writableEnded)
                return !0;
            const t = e._writableState;
            return (null == t || !t.errored) && ("boolean" != typeof (null == t ? void 0 : t.ended) ? null : t.ended)
        }
        function _(e, t) {
            if (!p(e))
                return null;
            const r = e._readableState;
            return (null == r || !r.errored) && ("boolean" != typeof (null == r ? void 0 : r.endEmitted) ? null : !!(r.endEmitted || !1 === t && !0 === r.ended && 0 === r.length))
        }
        function E(e) {
            return e && null != e[c] ? e[c] : "boolean" != typeof (null == e ? void 0 : e.readable) ? null : !w(e) && (p(e) && e.readable && !_(e))
        }
        function S(e) {
            return e && null != e[u] ? e[u] : "boolean" != typeof (null == e ? void 0 : e.writable) ? null : !w(e) && (h(e) && e.writable && !v(e))
        }
        function j(e) {
            return "boolean" == typeof e._closed && "boolean" == typeof e._defaultKeepAlive && "boolean" == typeof e._removedConnection && "boolean" == typeof e._removedContLen
        }
        function R(e) {
            return "boolean" == typeof e._sent100 && j(e)
        }
        t.exports = {
            isDestroyed: w,
            kIsDestroyed: i,
            isDisturbed: function(e) {
                var t;
                return !(!e || !(null !== (t = e[l]) && void 0 !== t ? t : e.readableDidRead || e.readableAborted))
            },
            kIsDisturbed: l,
            isErrored: function(e) {
                var t, r, n, s, o, i, c, u, l, d;
                return !(!e || !(null !== (t = null !== (r = null !== (n = null !== (s = null !== (o = null !== (i = e[a]) && void 0 !== i ? i : e.readableErrored) && void 0 !== o ? o : e.writableErrored) && void 0 !== s ? s : null === (c = e._readableState) || void 0 === c ? void 0 : c.errorEmitted) && void 0 !== n ? n : null === (u = e._writableState) || void 0 === u ? void 0 : u.errorEmitted) && void 0 !== r ? r : null === (l = e._readableState) || void 0 === l ? void 0 : l.errored) && void 0 !== t ? t : null === (d = e._writableState) || void 0 === d ? void 0 : d.errored))
            },
            kIsErrored: a,
            isReadable: E,
            kIsReadable: c,
            kIsClosedPromise: d,
            kControllerErrorFunction: f,
            kIsWritable: u,
            isClosed: function(e) {
                if (!g(e))
                    return null;
                if ("boolean" == typeof e.closed)
                    return e.closed;
                const t = e._writableState
                    , r = e._readableState;
                return "boolean" == typeof (null == t ? void 0 : t.closed) || "boolean" == typeof (null == r ? void 0 : r.closed) ? (null == t ? void 0 : t.closed) || (null == r ? void 0 : r.closed) : "boolean" == typeof e._closed && j(e) ? e._closed : null
            },
            isDuplexNodeStream: function(e) {
                return !(!e || "function" != typeof e.pipe || !e._readableState || "function" != typeof e.on || "function" != typeof e.write)
            },
            isFinished: function(e, t) {
                return g(e) ? !!w(e) || (!1 === (null == t ? void 0 : t.readable) || !E(e)) && (!1 === (null == t ? void 0 : t.writable) || !S(e)) : null
            },
            isIterable: function(e, t) {
                return null != e && (!0 === t ? "function" == typeof e[n] : !1 === t ? "function" == typeof e[s] : "function" == typeof e[n] || "function" == typeof e[s])
            },
            isReadableNodeStream: p,
            isReadableStream: m,
            isReadableEnded: function(e) {
                if (!p(e))
                    return null;
                if (!0 === e.readableEnded)
                    return !0;
                const t = e._readableState;
                return !(!t || t.errored) && ("boolean" != typeof (null == t ? void 0 : t.ended) ? null : t.ended)
            },
            isReadableFinished: _,
            isReadableErrored: function(e) {
                var t, r;
                return g(e) ? e.readableErrored ? e.readableErrored : null !== (t = null === (r = e._readableState) || void 0 === r ? void 0 : r.errored) && void 0 !== t ? t : null : null
            },
            isNodeStream: g,
            isWebStream: function(e) {
                return m(e) || b(e) || y(e)
            },
            isWritable: S,
            isWritableNodeStream: h,
            isWritableStream: b,
            isWritableEnded: v,
            isWritableFinished: function(e, t) {
                if (!h(e))
                    return null;
                if (!0 === e.writableFinished)
                    return !0;
                const r = e._writableState;
                return (null == r || !r.errored) && ("boolean" != typeof (null == r ? void 0 : r.finished) ? null : !!(r.finished || !1 === t && !0 === r.ended && 0 === r.length))
            },
            isWritableErrored: function(e) {
                var t, r;
                return g(e) ? e.writableErrored ? e.writableErrored : null !== (t = null === (r = e._writableState) || void 0 === r ? void 0 : r.errored) && void 0 !== t ? t : null : null
            },
            isServerRequest: function(e) {
                var t;
                return "boolean" == typeof e._consuming && "boolean" == typeof e._dumped && void 0 === (null === (t = e.req) || void 0 === t ? void 0 : t.upgradeOrConnect)
            },
            isServerResponse: R,
            willEmitClose: function(e) {
                if (!g(e))
                    return null;
                const t = e._writableState
                    , r = e._readableState
                    , n = t || r;
                return !n && R(e) || !!(n && n.autoDestroy && n.emitClose && !1 === n.closed)
            },
            isTransformStream: y
        }
    }
        , {
            "../../ours/primordials": 146
        }],
    142: [function(e, t, r) {
        const n = e("process/")
            , {ArrayPrototypeSlice: s, Error: o, FunctionPrototypeSymbolHasInstance: i, ObjectDefineProperty: a, ObjectDefineProperties: c, ObjectSetPrototypeOf: u, StringPrototypeToLowerCase: l, Symbol: d, SymbolHasInstance: f} = e("../../ours/primordials");
        t.exports = P,
            P.WritableState = x;
        const {EventEmitter: p} = e("events")
            , h = e("./legacy").Stream
            , {Buffer: g} = e("buffer")
            , m = e("./destroy")
            , {addAbortSignal: b} = e("./add-abort-signal")
            , {getHighWaterMark: y, getDefaultHighWaterMark: w} = e("./state")
            , {ERR_INVALID_ARG_TYPE: v, ERR_METHOD_NOT_IMPLEMENTED: _, ERR_MULTIPLE_CALLBACK: E, ERR_STREAM_CANNOT_PIPE: S, ERR_STREAM_DESTROYED: j, ERR_STREAM_ALREADY_FINISHED: R, ERR_STREAM_NULL_VALUES: I, ERR_STREAM_WRITE_AFTER_END: A, ERR_UNKNOWN_ENCODING: M} = e("../../ours/errors").codes
            , {errorOrDestroy: T} = m;
        function C() {}
        u(P.prototype, h.prototype),
            u(P, h);
        const O = d("kOnFinished");
        function x(t, r, n) {
            "boolean" != typeof n && (n = r instanceof e("./duplex")),
                this.objectMode = !(!t || !t.objectMode),
            n && (this.objectMode = this.objectMode || !(!t || !t.writableObjectMode)),
                this.highWaterMark = t ? y(this, t, "writableHighWaterMark", n) : w(!1),
                this.finalCalled = !1,
                this.needDrain = !1,
                this.ending = !1,
                this.ended = !1,
                this.finished = !1,
                this.destroyed = !1;
            const s = !(!t || !1 !== t.decodeStrings);
            this.decodeStrings = !s,
                this.defaultEncoding = t && t.defaultEncoding || "utf8",
                this.length = 0,
                this.writing = !1,
                this.corked = 0,
                this.sync = !0,
                this.bufferProcessing = !1,
                this.onwrite = B.bind(void 0, r),
                this.writecb = null,
                this.writelen = 0,
                this.afterWriteTickInfo = null,
                N(this),
                this.pendingcb = 0,
                this.constructed = !0,
                this.prefinished = !1,
                this.errorEmitted = !1,
                this.emitClose = !t || !1 !== t.emitClose,
                this.autoDestroy = !t || !1 !== t.autoDestroy,
                this.errored = null,
                this.closed = !1,
                this.closeEmitted = !1,
                this[O] = []
        }
        function N(e) {
            e.buffered = [],
                e.bufferedIndex = 0,
                e.allBuffers = !0,
                e.allNoop = !0
        }
        function P(t) {
            const r = this instanceof e("./duplex");
            if (!r && !i(P, this))
                return new P(t);
            this._writableState = new x(t,this,r),
            t && ("function" == typeof t.write && (this._write = t.write),
            "function" == typeof t.writev && (this._writev = t.writev),
            "function" == typeof t.destroy && (this._destroy = t.destroy),
            "function" == typeof t.final && (this._final = t.final),
            "function" == typeof t.construct && (this._construct = t.construct),
            t.signal && b(t.signal, this)),
                h.call(this, t),
                m.construct(this, ( () => {
                        const e = this._writableState;
                        e.writing || W(this, e),
                            G(this, e)
                    }
                ))
        }
        function k(e, t, r, s) {
            const o = e._writableState;
            if ("function" == typeof r)
                s = r,
                    r = o.defaultEncoding;
            else {
                if (r) {
                    if ("buffer" !== r && !g.isEncoding(r))
                        throw new M(r)
                } else
                    r = o.defaultEncoding;
                "function" != typeof s && (s = C)
            }
            if (null === t)
                throw new I;
            if (!o.objectMode)
                if ("string" == typeof t)
                    !1 !== o.decodeStrings && (t = g.from(t, r),
                        r = "buffer");
                else if (t instanceof g)
                    r = "buffer";
                else {
                    if (!h._isUint8Array(t))
                        throw new v("chunk",["string", "Buffer", "Uint8Array"],t);
                    t = h._uint8ArrayToBuffer(t),
                        r = "buffer"
                }
            let i;
            return o.ending ? i = new A : o.destroyed && (i = new j("write")),
                i ? (n.nextTick(s, i),
                    T(e, i, !0),
                    i) : (o.pendingcb++,
                    function(e, t, r, n, s) {
                        const o = t.objectMode ? 1 : r.length;
                        t.length += o;
                        const i = t.length < t.highWaterMark;
                        i || (t.needDrain = !0);
                        t.writing || t.corked || t.errored || !t.constructed ? (t.buffered.push({
                            chunk: r,
                            encoding: n,
                            callback: s
                        }),
                        t.allBuffers && "buffer" !== n && (t.allBuffers = !1),
                        t.allNoop && s !== C && (t.allNoop = !1)) : (t.writelen = o,
                            t.writecb = s,
                            t.writing = !0,
                            t.sync = !0,
                            e._write(r, n, t.onwrite),
                            t.sync = !1);
                        return i && !t.errored && !t.destroyed
                    }(e, o, t, r, s))
        }
        function L(e, t, r, n, s, o, i) {
            t.writelen = n,
                t.writecb = i,
                t.writing = !0,
                t.sync = !0,
                t.destroyed ? t.onwrite(new j("write")) : r ? e._writev(s, t.onwrite) : e._write(s, o, t.onwrite),
                t.sync = !1
        }
        function D(e, t, r, n) {
            --t.pendingcb,
                n(r),
                F(t),
                T(e, r)
        }
        function B(e, t) {
            const r = e._writableState
                , s = r.sync
                , o = r.writecb;
            "function" == typeof o ? (r.writing = !1,
                r.writecb = null,
                r.length -= r.writelen,
                r.writelen = 0,
                t ? (t.stack,
                r.errored || (r.errored = t),
                e._readableState && !e._readableState.errored && (e._readableState.errored = t),
                    s ? n.nextTick(D, e, r, t, o) : D(e, r, t, o)) : (r.buffered.length > r.bufferedIndex && W(e, r),
                    s ? null !== r.afterWriteTickInfo && r.afterWriteTickInfo.cb === o ? r.afterWriteTickInfo.count++ : (r.afterWriteTickInfo = {
                        count: 1,
                        cb: o,
                        stream: e,
                        state: r
                    },
                        n.nextTick($, r.afterWriteTickInfo)) : U(e, r, 1, o))) : T(e, new E)
        }
        function $({stream: e, state: t, count: r, cb: n}) {
            return t.afterWriteTickInfo = null,
                U(e, t, r, n)
        }
        function U(e, t, r, n) {
            for (!t.ending && !e.destroyed && 0 === t.length && t.needDrain && (t.needDrain = !1,
                e.emit("drain")); r-- > 0; )
                t.pendingcb--,
                    n();
            t.destroyed && F(t),
                G(e, t)
        }
        function F(e) {
            if (e.writing)
                return;
            for (let r = e.bufferedIndex; r < e.buffered.length; ++r) {
                var t;
                const {chunk: n, callback: s} = e.buffered[r]
                    , o = e.objectMode ? 1 : n.length;
                e.length -= o,
                    s(null !== (t = e.errored) && void 0 !== t ? t : new j("write"))
            }
            const r = e[O].splice(0);
            for (let t = 0; t < r.length; t++) {
                var n;
                r[t](null !== (n = e.errored) && void 0 !== n ? n : new j("end"))
            }
            N(e)
        }
        function W(e, t) {
            if (t.corked || t.bufferProcessing || t.destroyed || !t.constructed)
                return;
            const {buffered: r, bufferedIndex: n, objectMode: o} = t
                , i = r.length - n;
            if (!i)
                return;
            let a = n;
            if (t.bufferProcessing = !0,
            i > 1 && e._writev) {
                t.pendingcb -= i - 1;
                const n = t.allNoop ? C : e => {
                    for (let t = a; t < r.length; ++t)
                        r[t].callback(e)
                }
                    , o = t.allNoop && 0 === a ? r : s(r, a);
                o.allBuffers = t.allBuffers,
                    L(e, t, !0, t.length, o, "", n),
                    N(t)
            } else {
                do {
                    const {chunk: n, encoding: s, callback: i} = r[a];
                    r[a++] = null;
                    L(e, t, !1, o ? 1 : n.length, n, s, i)
                } while (a < r.length && !t.writing);
                a === r.length ? N(t) : a > 256 ? (r.splice(0, a),
                    t.bufferedIndex = 0) : t.bufferedIndex = a
            }
            t.bufferProcessing = !1
        }
        function z(e) {
            return e.ending && !e.destroyed && e.constructed && 0 === e.length && !e.errored && 0 === e.buffered.length && !e.finished && !e.writing && !e.errorEmitted && !e.closeEmitted
        }
        function V(e, t) {
            t.prefinished || t.finalCalled || ("function" != typeof e._final || t.destroyed ? (t.prefinished = !0,
                e.emit("prefinish")) : (t.finalCalled = !0,
                function(e, t) {
                    let r = !1;
                    function s(s) {
                        if (r)
                            T(e, null != s ? s : E());
                        else if (r = !0,
                            t.pendingcb--,
                            s) {
                            const r = t[O].splice(0);
                            for (let e = 0; e < r.length; e++)
                                r[e](s);
                            T(e, s, t.sync)
                        } else
                            z(t) && (t.prefinished = !0,
                                e.emit("prefinish"),
                                t.pendingcb++,
                                n.nextTick(H, e, t))
                    }
                    t.sync = !0,
                        t.pendingcb++;
                    try {
                        e._final(s)
                    } catch (e) {
                        s(e)
                    }
                    t.sync = !1
                }(e, t)))
        }
        function G(e, t, r) {
            z(t) && (V(e, t),
            0 === t.pendingcb && (r ? (t.pendingcb++,
                n.nextTick(( (e, t) => {
                        z(t) ? H(e, t) : t.pendingcb--
                    }
                ), e, t)) : z(t) && (t.pendingcb++,
                H(e, t))))
        }
        function H(e, t) {
            t.pendingcb--,
                t.finished = !0;
            const r = t[O].splice(0);
            for (let e = 0; e < r.length; e++)
                r[e]();
            if (e.emit("finish"),
                t.autoDestroy) {
                const t = e._readableState;
                (!t || t.autoDestroy && (t.endEmitted || !1 === t.readable)) && e.destroy()
            }
        }
        x.prototype.getBuffer = function() {
            return s(this.buffered, this.bufferedIndex)
        }
            ,
            a(x.prototype, "bufferedRequestCount", {
                __proto__: null,
                get() {
                    return this.buffered.length - this.bufferedIndex
                }
            }),
            a(P, f, {
                __proto__: null,
                value: function(e) {
                    return !!i(this, e) || this === P && (e && e._writableState instanceof x)
                }
            }),
            P.prototype.pipe = function() {
                T(this, new S)
            }
            ,
            P.prototype.write = function(e, t, r) {
                return !0 === k(this, e, t, r)
            }
            ,
            P.prototype.cork = function() {
                this._writableState.corked++
            }
            ,
            P.prototype.uncork = function() {
                const e = this._writableState;
                e.corked && (e.corked--,
                e.writing || W(this, e))
            }
            ,
            P.prototype.setDefaultEncoding = function(e) {
                if ("string" == typeof e && (e = l(e)),
                    !g.isEncoding(e))
                    throw new M(e);
                return this._writableState.defaultEncoding = e,
                    this
            }
            ,
            P.prototype._write = function(e, t, r) {
                if (!this._writev)
                    throw new _("_write()");
                this._writev([{
                    chunk: e,
                    encoding: t
                }], r)
            }
            ,
            P.prototype._writev = null,
            P.prototype.end = function(e, t, r) {
                const s = this._writableState;
                let i;
                if ("function" == typeof e ? (r = e,
                    e = null,
                    t = null) : "function" == typeof t && (r = t,
                    t = null),
                null != e) {
                    const r = k(this, e, t);
                    r instanceof o && (i = r)
                }
                return s.corked && (s.corked = 1,
                    this.uncork()),
                i || (s.errored || s.ending ? s.finished ? i = new R("end") : s.destroyed && (i = new j("end")) : (s.ending = !0,
                    G(this, s, !0),
                    s.ended = !0)),
                "function" == typeof r && (i || s.finished ? n.nextTick(r, i) : s[O].push(r)),
                    this
            }
            ,
            c(P.prototype, {
                closed: {
                    __proto__: null,
                    get() {
                        return !!this._writableState && this._writableState.closed
                    }
                },
                destroyed: {
                    __proto__: null,
                    get() {
                        return !!this._writableState && this._writableState.destroyed
                    },
                    set(e) {
                        this._writableState && (this._writableState.destroyed = e)
                    }
                },
                writable: {
                    __proto__: null,
                    get() {
                        const e = this._writableState;
                        return !(!e || !1 === e.writable || e.destroyed || e.errored || e.ending || e.ended)
                    },
                    set(e) {
                        this._writableState && (this._writableState.writable = !!e)
                    }
                },
                writableFinished: {
                    __proto__: null,
                    get() {
                        return !!this._writableState && this._writableState.finished
                    }
                },
                writableObjectMode: {
                    __proto__: null,
                    get() {
                        return !!this._writableState && this._writableState.objectMode
                    }
                },
                writableBuffer: {
                    __proto__: null,
                    get() {
                        return this._writableState && this._writableState.getBuffer()
                    }
                },
                writableEnded: {
                    __proto__: null,
                    get() {
                        return !!this._writableState && this._writableState.ending
                    }
                },
                writableNeedDrain: {
                    __proto__: null,
                    get() {
                        const e = this._writableState;
                        return !!e && (!e.destroyed && !e.ending && e.needDrain)
                    }
                },
                writableHighWaterMark: {
                    __proto__: null,
                    get() {
                        return this._writableState && this._writableState.highWaterMark
                    }
                },
                writableCorked: {
                    __proto__: null,
                    get() {
                        return this._writableState ? this._writableState.corked : 0
                    }
                },
                writableLength: {
                    __proto__: null,
                    get() {
                        return this._writableState && this._writableState.length
                    }
                },
                errored: {
                    __proto__: null,
                    enumerable: !1,
                    get() {
                        return this._writableState ? this._writableState.errored : null
                    }
                },
                writableAborted: {
                    __proto__: null,
                    enumerable: !1,
                    get: function() {
                        return !(!1 === this._writableState.writable || !this._writableState.destroyed && !this._writableState.errored || this._writableState.finished)
                    }
                }
            });
        const J = m.destroy;
        let q;
        function X() {
            return void 0 === q && (q = {}),
                q
        }
        P.prototype.destroy = function(e, t) {
            const r = this._writableState;
            return !r.destroyed && (r.bufferedIndex < r.buffered.length || r[O].length) && n.nextTick(F, r),
                J.call(this, e, t),
                this
        }
            ,
            P.prototype._undestroy = m.undestroy,
            P.prototype._destroy = function(e, t) {
                t(e)
            }
            ,
            P.prototype[p.captureRejectionSymbol] = function(e) {
                this.destroy(e)
            }
            ,
            P.fromWeb = function(e, t) {
                return X().newStreamWritableFromWritableStream(e, t)
            }
            ,
            P.toWeb = function(e) {
                return X().newWritableStreamFromStreamWritable(e)
            }
    }
        , {
            "../../ours/errors": 145,
            "../../ours/primordials": 146,
            "./add-abort-signal": 126,
            "./destroy": 129,
            "./duplex": 130,
            "./legacy": 134,
            "./state": 139,
            buffer: 195,
            events: 200,
            "process/": 211
        }],
    143: [function(e, t, r) {
        "use strict";
        const {ArrayIsArray: n, ArrayPrototypeIncludes: s, ArrayPrototypeJoin: o, ArrayPrototypeMap: i, NumberIsInteger: a, NumberIsNaN: c, NumberMAX_SAFE_INTEGER: u, NumberMIN_SAFE_INTEGER: l, NumberParseInt: d, ObjectPrototypeHasOwnProperty: f, RegExpPrototypeExec: p, String: h, StringPrototypeToUpperCase: g, StringPrototypeTrim: m} = e("../ours/primordials")
            , {hideStackFrames: b, codes: {ERR_SOCKET_BAD_PORT: y, ERR_INVALID_ARG_TYPE: w, ERR_INVALID_ARG_VALUE: v, ERR_OUT_OF_RANGE: _, ERR_UNKNOWN_SIGNAL: E}} = e("../ours/errors")
            , {normalizeEncoding: S} = e("../ours/util")
            , {isAsyncFunction: j, isArrayBufferView: R} = e("../ours/util").types
            , I = {};
        const A = /^[0-7]+$/;
        const M = b(( (e, t, r=l, n=u) => {
                if ("number" != typeof e)
                    throw new w(t,"number",e);
                if (!a(e))
                    throw new _(t,"an integer",e);
                if (e < r || e > n)
                    throw new _(t,`>= ${r} && <= ${n}`,e)
            }
        ))
            , T = b(( (e, t, r=-2147483648, n=2147483647) => {
                if ("number" != typeof e)
                    throw new w(t,"number",e);
                if (!a(e))
                    throw new _(t,"an integer",e);
                if (e < r || e > n)
                    throw new _(t,`>= ${r} && <= ${n}`,e)
            }
        ))
            , C = b(( (e, t, r=!1) => {
                if ("number" != typeof e)
                    throw new w(t,"number",e);
                if (!a(e))
                    throw new _(t,"an integer",e);
                const n = r ? 1 : 0
                    , s = 4294967295;
                if (e < n || e > s)
                    throw new _(t,`>= ${n} && <= ${s}`,e)
            }
        ));
        function O(e, t) {
            if ("string" != typeof e)
                throw new w(t,"string",e)
        }
        const x = b(( (e, t, r) => {
                if (!s(r, e)) {
                    const n = o(i(r, (e => "string" == typeof e ? `'${e}'` : h(e))), ", ");
                    throw new v(t,e,"must be one of: " + n)
                }
            }
        ));
        function N(e, t) {
            if ("boolean" != typeof e)
                throw new w(t,"boolean",e)
        }
        function P(e, t, r) {
            return null != e && f(e, t) ? e[t] : r
        }
        const k = b(( (e, t, r=null) => {
                const s = P(r, "allowArray", !1)
                    , o = P(r, "allowFunction", !1);
                if (!P(r, "nullable", !1) && null === e || !s && n(e) || "object" != typeof e && (!o || "function" != typeof e))
                    throw new w(t,"Object",e)
            }
        ))
            , L = b(( (e, t) => {
                if (null != e && "object" != typeof e && "function" != typeof e)
                    throw new w(t,"a dictionary",e)
            }
        ))
            , D = b(( (e, t, r=0) => {
                if (!n(e))
                    throw new w(t,"Array",e);
                if (e.length < r) {
                    throw new v(t,e,`must be longer than ${r}`)
                }
            }
        ));
        const B = b(( (e, t="buffer") => {
                if (!R(e))
                    throw new w(t,["Buffer", "TypedArray", "DataView"],e)
            }
        ));
        const $ = b(( (e, t) => {
                if (void 0 !== e && (null === e || "object" != typeof e || !("aborted"in e)))
                    throw new w(t,"AbortSignal",e)
            }
        ))
            , U = b(( (e, t) => {
                if ("function" != typeof e)
                    throw new w(t,"Function",e)
            }
        ))
            , F = b(( (e, t) => {
                if ("function" != typeof e || j(e))
                    throw new w(t,"Function",e)
            }
        ))
            , W = b(( (e, t) => {
                if (void 0 !== e)
                    throw new w(t,"undefined",e)
            }
        ));
        const z = /^(?:<[^>]*>)(?:\s*;\s*[^;"\s]+(?:=(")?[^;"\s]*\1)?)*$/;
        function V(e, t) {
            if (void 0 === e || !p(z, e))
                throw new v(t,e,'must be an array or string of format "</styles.css>; rel=preload; as=style"')
        }
        t.exports = {
            isInt32: function(e) {
                return e === (0 | e)
            },
            isUint32: function(e) {
                return e === e >>> 0
            },
            parseFileMode: function(e, t, r) {
                if (void 0 === e && (e = r),
                "string" == typeof e) {
                    if (null === p(A, e))
                        throw new v(t,e,"must be a 32-bit unsigned integer or an octal string");
                    e = d(e, 8)
                }
                return C(e, t),
                    e
            },
            validateArray: D,
            validateStringArray: function(e, t) {
                D(e, t);
                for (let r = 0; r < e.length; r++)
                    O(e[r], `${t}[${r}]`)
            },
            validateBooleanArray: function(e, t) {
                D(e, t);
                for (let r = 0; r < e.length; r++)
                    N(e[r], `${t}[${r}]`)
            },
            validateAbortSignalArray: function(e, t) {
                D(e, t);
                for (let r = 0; r < e.length; r++) {
                    const n = e[r]
                        , s = `${t}[${r}]`;
                    if (null == n)
                        throw new w(s,"AbortSignal",n);
                    $(n, s)
                }
            },
            validateBoolean: N,
            validateBuffer: B,
            validateDictionary: L,
            validateEncoding: function(e, t) {
                const r = S(t)
                    , n = e.length;
                if ("hex" === r && n % 2 != 0)
                    throw new v("encoding",t,`is invalid for data of length ${n}`)
            },
            validateFunction: U,
            validateInt32: T,
            validateInteger: M,
            validateNumber: function(e, t, r=void 0, n) {
                if ("number" != typeof e)
                    throw new w(t,"number",e);
                if (null != r && e < r || null != n && e > n || (null != r || null != n) && c(e))
                    throw new _(t,`${null != r ? `>= ${r}` : ""}${null != r && null != n ? " && " : ""}${null != n ? `<= ${n}` : ""}`,e)
            },
            validateObject: k,
            validateOneOf: x,
            validatePlainFunction: F,
            validatePort: function(e, t="Port", r=!0) {
                if ("number" != typeof e && "string" != typeof e || "string" == typeof e && 0 === m(e).length || +e != +e >>> 0 || e > 65535 || 0 === e && !r)
                    throw new y(t,e,r);
                return 0 | e
            },
            validateSignalName: function(e, t="signal") {
                if (O(e, t),
                void 0 === I[e]) {
                    if (void 0 !== I[g(e)])
                        throw new E(e + " (signals must use all capital letters)");
                    throw new E(e)
                }
            },
            validateString: O,
            validateUint32: C,
            validateUndefined: W,
            validateUnion: function(e, t, r) {
                if (!s(r, e))
                    throw new w(t,`('${o(r, "|")}')`,e)
            },
            validateAbortSignal: $,
            validateLinkHeaderValue: function(e) {
                if ("string" == typeof e)
                    return V(e, "hints"),
                        e;
                if (n(e)) {
                    const t = e.length;
                    let r = "";
                    if (0 === t)
                        return r;
                    for (let n = 0; n < t; n++) {
                        const s = e[n];
                        V(s, "hints"),
                            r += s,
                        n !== t - 1 && (r += ", ")
                    }
                    return r
                }
                throw new v("hints",e,'must be an array or string of format "</styles.css>; rel=preload; as=style"')
            }
        }
    }
        , {
            "../ours/errors": 145,
            "../ours/primordials": 146,
            "../ours/util": 147
        }],
    144: [function(e, t, r) {
        "use strict";
        const n = e("../stream")
            , s = e("../stream/promises")
            , o = n.Readable.destroy;
        t.exports = n.Readable,
            t.exports._uint8ArrayToBuffer = n._uint8ArrayToBuffer,
            t.exports._isUint8Array = n._isUint8Array,
            t.exports.isDisturbed = n.isDisturbed,
            t.exports.isErrored = n.isErrored,
            t.exports.isReadable = n.isReadable,
            t.exports.Readable = n.Readable,
            t.exports.Writable = n.Writable,
            t.exports.Duplex = n.Duplex,
            t.exports.Transform = n.Transform,
            t.exports.PassThrough = n.PassThrough,
            t.exports.addAbortSignal = n.addAbortSignal,
            t.exports.finished = n.finished,
            t.exports.destroy = n.destroy,
            t.exports.destroy = o,
            t.exports.pipeline = n.pipeline,
            t.exports.compose = n.compose,
            Object.defineProperty(n, "promises", {
                configurable: !0,
                enumerable: !0,
                get: () => s
            }),
            t.exports.Stream = n.Stream,
            t.exports.default = t.exports
    }
        , {
            "../stream": 148,
            "../stream/promises": 149
        }],
    145: [function(e, t, r) {
        "use strict";
        const {format: n, inspect: s, AggregateError: o} = e("./util")
            , i = globalThis.AggregateError || o
            , a = Symbol("kIsNodeError")
            , c = ["string", "function", "number", "object", "Function", "Object", "boolean", "bigint", "symbol"]
            , u = /^([A-Z][a-z0-9]*)+$/
            , l = {};
        function d(e, t) {
            if (!e)
                throw new l.ERR_INTERNAL_ASSERTION(t)
        }
        function f(e) {
            let t = ""
                , r = e.length;
            const n = "-" === e[0] ? 1 : 0;
            for (; r >= n + 4; r -= 3)
                t = `_${e.slice(r - 3, r)}${t}`;
            return `${e.slice(0, r)}${t}`
        }
        function p(e, t, r) {
            r || (r = Error);
            class s extends r {
                constructor(...r) {
                    super(function(e, t, r) {
                        if ("function" == typeof t)
                            return d(t.length <= r.length, `Code: ${e}; The provided arguments length (${r.length}) does not match the required ones (${t.length}).`),
                                t(...r);
                        const s = (t.match(/%[dfijoOs]/g) || []).length;
                        return d(s === r.length, `Code: ${e}; The provided arguments length (${r.length}) does not match the required ones (${s}).`),
                            0 === r.length ? t : n(t, ...r)
                    }(e, t, r))
                }
                toString() {
                    return `${this.name} [${e}]: ${this.message}`
                }
            }
            Object.defineProperties(s.prototype, {
                name: {
                    value: r.name,
                    writable: !0,
                    enumerable: !1,
                    configurable: !0
                },
                toString: {
                    value() {
                        return `${this.name} [${e}]: ${this.message}`
                    },
                    writable: !0,
                    enumerable: !1,
                    configurable: !0
                }
            }),
                s.prototype.code = e,
                s.prototype[a] = !0,
                l[e] = s
        }
        function h(e) {
            const t = "__node_internal_" + e.name;
            return Object.defineProperty(e, "name", {
                value: t
            }),
                e
        }
        class g extends Error {
            constructor(e="The operation was aborted", t=void 0) {
                if (void 0 !== t && "object" != typeof t)
                    throw new l.ERR_INVALID_ARG_TYPE("options","Object",t);
                super(e, t),
                    this.code = "ABORT_ERR",
                    this.name = "AbortError"
            }
        }
        p("ERR_ASSERTION", "%s", Error),
            p("ERR_INVALID_ARG_TYPE", ( (e, t, r) => {
                    d("string" == typeof e, "'name' must be a string"),
                    Array.isArray(t) || (t = [t]);
                    let n = "The ";
                    e.endsWith(" argument") ? n += `${e} ` : n += `"${e}" ${e.includes(".") ? "property" : "argument"} `,
                        n += "must be ";
                    const o = []
                        , i = []
                        , a = [];
                    for (const e of t)
                        d("string" == typeof e, "All expected entries have to be of type string"),
                            c.includes(e) ? o.push(e.toLowerCase()) : u.test(e) ? i.push(e) : (d("object" !== e, 'The value "object" should be written as "Object"'),
                                a.push(e));
                    if (i.length > 0) {
                        const e = o.indexOf("object");
                        -1 !== e && (o.splice(o, e, 1),
                            i.push("Object"))
                    }
                    if (o.length > 0) {
                        switch (o.length) {
                            case 1:
                                n += `of type ${o[0]}`;
                                break;
                            case 2:
                                n += `one of type ${o[0]} or ${o[1]}`;
                                break;
                            default:
                            {
                                const e = o.pop();
                                n += `one of type ${o.join(", ")}, or ${e}`
                            }
                        }
                        (i.length > 0 || a.length > 0) && (n += " or ")
                    }
                    if (i.length > 0) {
                        switch (i.length) {
                            case 1:
                                n += `an instance of ${i[0]}`;
                                break;
                            case 2:
                                n += `an instance of ${i[0]} or ${i[1]}`;
                                break;
                            default:
                            {
                                const e = i.pop();
                                n += `an instance of ${i.join(", ")}, or ${e}`
                            }
                        }
                        a.length > 0 && (n += " or ")
                    }
                    switch (a.length) {
                        case 0:
                            break;
                        case 1:
                            a[0].toLowerCase() !== a[0] && (n += "an "),
                                n += `${a[0]}`;
                            break;
                        case 2:
                            n += `one of ${a[0]} or ${a[1]}`;
                            break;
                        default:
                        {
                            const e = a.pop();
                            n += `one of ${a.join(", ")}, or ${e}`
                        }
                    }
                    if (null == r)
                        n += `. Received ${r}`;
                    else if ("function" == typeof r && r.name)
                        n += `. Received function ${r.name}`;
                    else if ("object" == typeof r) {
                        var l;
                        if (null !== (l = r.constructor) && void 0 !== l && l.name)
                            n += `. Received an instance of ${r.constructor.name}`;
                        else {
                            n += `. Received ${s(r, {
                                depth: -1
                            })}`
                        }
                    } else {
                        let e = s(r, {
                            colors: !1
                        });
                        e.length > 25 && (e = `${e.slice(0, 25)}...`),
                            n += `. Received type ${typeof r} (${e})`
                    }
                    return n
                }
            ), TypeError),
            p("ERR_INVALID_ARG_VALUE", ( (e, t, r="is invalid") => {
                    let n = s(t);
                    n.length > 128 && (n = n.slice(0, 128) + "...");
                    return `The ${e.includes(".") ? "property" : "argument"} '${e}' ${r}. Received ${n}`
                }
            ), TypeError),
            p("ERR_INVALID_RETURN_VALUE", ( (e, t, r) => {
                    var n;
                    return `Expected ${e} to be returned from the "${t}" function but got ${null != r && null !== (n = r.constructor) && void 0 !== n && n.name ? `instance of ${r.constructor.name}` : "type " + typeof r}.`
                }
            ), TypeError),
            p("ERR_MISSING_ARGS", ( (...e) => {
                    let t;
                    d(e.length > 0, "At least one arg needs to be specified");
                    const r = e.length;
                    switch (e = (Array.isArray(e) ? e : [e]).map((e => `"${e}"`)).join(" or "),
                        r) {
                        case 1:
                            t += `The ${e[0]} argument`;
                            break;
                        case 2:
                            t += `The ${e[0]} and ${e[1]} arguments`;
                            break;
                        default:
                        {
                            const r = e.pop();
                            t += `The ${e.join(", ")}, and ${r} arguments`
                        }
                    }
                    return `${t} must be specified`
                }
            ), TypeError),
            p("ERR_OUT_OF_RANGE", ( (e, t, r) => {
                    let n;
                    return d(t, 'Missing "range" argument'),
                        Number.isInteger(r) && Math.abs(r) > 2 ** 32 ? n = f(String(r)) : "bigint" == typeof r ? (n = String(r),
                        (r > 2n ** 32n || r < -(2n ** 32n)) && (n = f(n)),
                            n += "n") : n = s(r),
                        `The value of "${e}" is out of range. It must be ${t}. Received ${n}`
                }
            ), RangeError),
            p("ERR_MULTIPLE_CALLBACK", "Callback called multiple times", Error),
            p("ERR_METHOD_NOT_IMPLEMENTED", "The %s method is not implemented", Error),
            p("ERR_STREAM_ALREADY_FINISHED", "Cannot call %s after a stream was finished", Error),
            p("ERR_STREAM_CANNOT_PIPE", "Cannot pipe, not readable", Error),
            p("ERR_STREAM_DESTROYED", "Cannot call %s after a stream was destroyed", Error),
            p("ERR_STREAM_NULL_VALUES", "May not write null values to stream", TypeError),
            p("ERR_STREAM_PREMATURE_CLOSE", "Premature close", Error),
            p("ERR_STREAM_PUSH_AFTER_EOF", "stream.push() after EOF", Error),
            p("ERR_STREAM_UNSHIFT_AFTER_END_EVENT", "stream.unshift() after end event", Error),
            p("ERR_STREAM_WRITE_AFTER_END", "write after end", Error),
            p("ERR_UNKNOWN_ENCODING", "Unknown encoding: %s", TypeError),
            t.exports = {
                AbortError: g,
                aggregateTwoErrors: h((function(e, t) {
                        if (e && t && e !== t) {
                            if (Array.isArray(t.errors))
                                return t.errors.push(e),
                                    t;
                            const r = new i([t, e],t.message);
                            return r.code = t.code,
                                r
                        }
                        return e || t
                    }
                )),
                hideStackFrames: h,
                codes: l
            }
    }
        , {
            "./util": 147
        }],
    146: [function(e, t, r) {
        "use strict";
        t.exports = {
            ArrayIsArray: e => Array.isArray(e),
            ArrayPrototypeIncludes: (e, t) => e.includes(t),
            ArrayPrototypeIndexOf: (e, t) => e.indexOf(t),
            ArrayPrototypeJoin: (e, t) => e.join(t),
            ArrayPrototypeMap: (e, t) => e.map(t),
            ArrayPrototypePop: (e, t) => e.pop(t),
            ArrayPrototypePush: (e, t) => e.push(t),
            ArrayPrototypeSlice: (e, t, r) => e.slice(t, r),
            Error: Error,
            FunctionPrototypeCall: (e, t, ...r) => e.call(t, ...r),
            FunctionPrototypeSymbolHasInstance: (e, t) => Function.prototype[Symbol.hasInstance].call(e, t),
            MathFloor: Math.floor,
            Number: Number,
            NumberIsInteger: Number.isInteger,
            NumberIsNaN: Number.isNaN,
            NumberMAX_SAFE_INTEGER: Number.MAX_SAFE_INTEGER,
            NumberMIN_SAFE_INTEGER: Number.MIN_SAFE_INTEGER,
            NumberParseInt: Number.parseInt,
            ObjectDefineProperties: (e, t) => Object.defineProperties(e, t),
            ObjectDefineProperty: (e, t, r) => Object.defineProperty(e, t, r),
            ObjectGetOwnPropertyDescriptor: (e, t) => Object.getOwnPropertyDescriptor(e, t),
            ObjectKeys: e => Object.keys(e),
            ObjectSetPrototypeOf: (e, t) => Object.setPrototypeOf(e, t),
            Promise: Promise,
            PromisePrototypeCatch: (e, t) => e.catch(t),
            PromisePrototypeThen: (e, t, r) => e.then(t, r),
            PromiseReject: e => Promise.reject(e),
            PromiseResolve: e => Promise.resolve(e),
            ReflectApply: Reflect.apply,
            RegExpPrototypeTest: (e, t) => e.test(t),
            SafeSet: Set,
            String: String,
            StringPrototypeSlice: (e, t, r) => e.slice(t, r),
            StringPrototypeToLowerCase: e => e.toLowerCase(),
            StringPrototypeToUpperCase: e => e.toUpperCase(),
            StringPrototypeTrim: e => e.trim(),
            Symbol: Symbol,
            SymbolFor: Symbol.for,
            SymbolAsyncIterator: Symbol.asyncIterator,
            SymbolHasInstance: Symbol.hasInstance,
            SymbolIterator: Symbol.iterator,
            SymbolDispose: Symbol.dispose || Symbol("Symbol.dispose"),
            SymbolAsyncDispose: Symbol.asyncDispose || Symbol("Symbol.asyncDispose"),
            TypedArrayPrototypeSet: (e, t, r) => e.set(t, r),
            Boolean: Boolean,
            Uint8Array: Uint8Array
        }
    }
        , {}],
    147: [function(e, t, r) {
        "use strict";
        const n = e("buffer")
            , {kResistStopPropagation: s, SymbolDispose: o} = e("./primordials")
            , i = globalThis.AbortSignal || e("abort-controller").AbortSignal
            , a = globalThis.AbortController || e("abort-controller").AbortController
            , c = Object.getPrototypeOf((async function() {}
            )).constructor
            , u = globalThis.Blob || n.Blob
            , l = void 0 !== u ? function(e) {
                    return e instanceof u
                }
                : function(e) {
                    return !1
                }
            , d = (e, t) => {
                if (void 0 !== e && (null === e || "object" != typeof e || !("aborted"in e)))
                    throw new ERR_INVALID_ARG_TYPE(t,"AbortSignal",e)
            }
        ;
        class f extends Error {
            constructor(e) {
                if (!Array.isArray(e))
                    throw new TypeError("Expected input to be an Array, got " + typeof e);
                let t = "";
                for (let r = 0; r < e.length; r++)
                    t += `    ${e[r].stack}\n`;
                super(t),
                    this.name = "AggregateError",
                    this.errors = e
            }
        }
        t.exports = {
            AggregateError: f,
            kEmptyObject: Object.freeze({}),
            once(e) {
                let t = !1;
                return function(...r) {
                    t || (t = !0,
                        e.apply(this, r))
                }
            },
            createDeferredPromise: function() {
                let e, t;
                return {
                    promise: new Promise(( (r, n) => {
                            e = r,
                                t = n
                        }
                    )),
                    resolve: e,
                    reject: t
                }
            },
            promisify: e => new Promise(( (t, r) => {
                    e(( (e, ...n) => e ? r(e) : t(...n)))
                }
            )),
            debuglog: () => function() {}
            ,
            format: (e, ...t) => e.replace(/%([sdifj])/g, (function(...[e,r]) {
                    const n = t.shift();
                    if ("f" === r)
                        return n.toFixed(6);
                    if ("j" === r)
                        return JSON.stringify(n);
                    if ("s" === r && "object" == typeof n) {
                        return `${n.constructor !== Object ? n.constructor.name : ""} {}`.trim()
                    }
                    return n.toString()
                }
            )),
            inspect(e) {
                switch (typeof e) {
                    case "string":
                        if (e.includes("'")) {
                            if (!e.includes('"'))
                                return `"${e}"`;
                            if (!e.includes("`") && !e.includes("${"))
                                return `\`${e}\``
                        }
                        return `'${e}'`;
                    case "number":
                        return isNaN(e) ? "NaN" : Object.is(e, -0) ? String(e) : e;
                    case "bigint":
                        return `${String(e)}n`;
                    case "boolean":
                    case "undefined":
                        return String(e);
                    case "object":
                        return "{}"
                }
            },
            types: {
                isAsyncFunction: e => e instanceof c,
                isArrayBufferView: e => ArrayBuffer.isView(e)
            },
            isBlob: l,
            deprecate: (e, t) => e,
            addAbortListener: e("events").addAbortListener || function(e, t) {
                if (void 0 === e)
                    throw new ERR_INVALID_ARG_TYPE("signal","AbortSignal",e);
                let r;
                return d(e, "signal"),
                    ( (e, t) => {
                            if ("function" != typeof e)
                                throw new ERR_INVALID_ARG_TYPE(t,"Function",e)
                        }
                    )(t, "listener"),
                    e.aborted ? queueMicrotask(( () => t())) : (e.addEventListener("abort", t, {
                            __proto__: null,
                            once: !0,
                            [s]: !0
                        }),
                            r = () => {
                                e.removeEventListener("abort", t)
                            }
                    ),
                    {
                        __proto__: null,
                        [o]() {
                            var e;
                            null === (e = r) || void 0 === e || e()
                        }
                    }
            }
            ,
            AbortSignalAny: i.any || function(e) {
                if (1 === e.length)
                    return e[0];
                const t = new a
                    , r = () => t.abort();
                return e.forEach((e => {
                        d(e, "signals"),
                            e.addEventListener("abort", r, {
                                once: !0
                            })
                    }
                )),
                    t.signal.addEventListener("abort", ( () => {
                            e.forEach((e => e.removeEventListener("abort", r)))
                        }
                    ), {
                        once: !0
                    }),
                    t.signal
            }
        },
            t.exports.promisify.custom = Symbol.for("nodejs.util.promisify.custom")
    }
        , {
            "./primordials": 146,
            "abort-controller": 192,
            buffer: 195,
            events: 200
        }],
    148: [function(e, t, r) {
        const {Buffer: n} = e("buffer")
            , {ObjectDefineProperty: s, ObjectKeys: o, ReflectApply: i} = e("./ours/primordials")
            , {promisify: {custom: a}} = e("./ours/util")
            , {streamReturningOperators: c, promiseReturningOperators: u} = e("./internal/streams/operators")
            , {codes: {ERR_ILLEGAL_CONSTRUCTOR: l}} = e("./ours/errors")
            , d = e("./internal/streams/compose")
            , {setDefaultHighWaterMark: f, getDefaultHighWaterMark: p} = e("./internal/streams/state")
            , {pipeline: h} = e("./internal/streams/pipeline")
            , {destroyer: g} = e("./internal/streams/destroy")
            , m = e("./internal/streams/end-of-stream")
            , b = e("./stream/promises")
            , y = e("./internal/streams/utils")
            , w = t.exports = e("./internal/streams/legacy").Stream;
        w.isDestroyed = y.isDestroyed,
            w.isDisturbed = y.isDisturbed,
            w.isErrored = y.isErrored,
            w.isReadable = y.isReadable,
            w.isWritable = y.isWritable,
            w.Readable = e("./internal/streams/readable");
        for (const E of o(c)) {
            const S = c[E];
            function v(...e) {
                if (new.target)
                    throw l();
                return w.Readable.from(i(S, this, e))
            }
            s(v, "name", {
                __proto__: null,
                value: S.name
            }),
                s(v, "length", {
                    __proto__: null,
                    value: S.length
                }),
                s(w.Readable.prototype, E, {
                    __proto__: null,
                    value: v,
                    enumerable: !1,
                    configurable: !0,
                    writable: !0
                })
        }
        for (const j of o(u)) {
            const R = u[j];
            function v(...e) {
                if (new.target)
                    throw l();
                return i(R, this, e)
            }
            s(v, "name", {
                __proto__: null,
                value: R.name
            }),
                s(v, "length", {
                    __proto__: null,
                    value: R.length
                }),
                s(w.Readable.prototype, j, {
                    __proto__: null,
                    value: v,
                    enumerable: !1,
                    configurable: !0,
                    writable: !0
                })
        }
        w.Writable = e("./internal/streams/writable"),
            w.Duplex = e("./internal/streams/duplex"),
            w.Transform = e("./internal/streams/transform"),
            w.PassThrough = e("./internal/streams/passthrough"),
            w.pipeline = h;
        const {addAbortSignal: _} = e("./internal/streams/add-abort-signal");
        w.addAbortSignal = _,
            w.finished = m,
            w.destroy = g,
            w.compose = d,
            w.setDefaultHighWaterMark = f,
            w.getDefaultHighWaterMark = p,
            s(w, "promises", {
                __proto__: null,
                configurable: !0,
                enumerable: !0,
                get: () => b
            }),
            s(h, a, {
                __proto__: null,
                enumerable: !0,
                get: () => b.pipeline
            }),
            s(m, a, {
                __proto__: null,
                enumerable: !0,
                get: () => b.finished
            }),
            w.Stream = w,
            w._isUint8Array = function(e) {
                return e instanceof Uint8Array
            }
            ,
            w._uint8ArrayToBuffer = function(e) {
                return n.from(e.buffer, e.byteOffset, e.byteLength)
            }
    }
        , {
            "./internal/streams/add-abort-signal": 126,
            "./internal/streams/compose": 128,
            "./internal/streams/destroy": 129,
            "./internal/streams/duplex": 130,
            "./internal/streams/end-of-stream": 132,
            "./internal/streams/legacy": 134,
            "./internal/streams/operators": 135,
            "./internal/streams/passthrough": 136,
            "./internal/streams/pipeline": 137,
            "./internal/streams/readable": 138,
            "./internal/streams/state": 139,
            "./internal/streams/transform": 140,
            "./internal/streams/utils": 141,
            "./internal/streams/writable": 142,
            "./ours/errors": 145,
            "./ours/primordials": 146,
            "./ours/util": 147,
            "./stream/promises": 149,
            buffer: 195
        }],
    149: [function(e, t, r) {
        "use strict";
        const {ArrayPrototypePop: n, Promise: s} = e("../ours/primordials")
            , {isIterable: o, isNodeStream: i, isWebStream: a} = e("../internal/streams/utils")
            , {pipelineImpl: c} = e("../internal/streams/pipeline")
            , {finished: u} = e("../internal/streams/end-of-stream");
        e("../../lib/stream.js"),
            t.exports = {
                finished: u,
                pipeline: function(...e) {
                    return new s(( (t, r) => {
                            let s, u;
                            const l = e[e.length - 1];
                            if (l && "object" == typeof l && !i(l) && !o(l) && !a(l)) {
                                const t = n(e);
                                s = t.signal,
                                    u = t.end
                            }
                            c(e, ( (e, n) => {
                                    e ? r(e) : t(n)
                                }
                            ), {
                                signal: s,
                                end: u
                            })
                        }
                    ))
                }
            }
    }
        , {
            "../../lib/stream.js": 148,
            "../internal/streams/end-of-stream": 132,
            "../internal/streams/pipeline": 137,
            "../internal/streams/utils": 141,
            "../ours/primordials": 146
        }],
    150: [function(e, t, r) {
        "use strict";
        var n = this && this.__importDefault || function(e) {
                return e && e.__esModule ? e : {
                    default: e
                }
            }
        ;
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.EthereumProviderError = r.JsonRpcError = void 0;
        const s = e("@metamask/utils")
            , o = n(e("fast-safe-stringify"))
            , i = e("./utils.cjs");
        class a extends Error {
            constructor(e, t, r) {
                if (!Number.isInteger(e))
                    throw new Error('"code" must be an integer.');
                if (!t || "string" != typeof t)
                    throw new Error('"message" must be a non-empty string.');
                (0,
                    i.dataHasCause)(r) ? (super(t, {
                    cause: r.cause
                }),
                (0,
                    s.hasProperty)(this, "cause") || Object.assign(this, {
                    cause: r.cause
                })) : super(t),
                void 0 !== r && (this.data = r),
                    this.code = e
            }
            serialize() {
                const e = {
                    code: this.code,
                    message: this.message
                };
                return void 0 !== this.data && (e.data = this.data,
                (0,
                    s.isPlainObject)(this.data) && (e.data.cause = (0,
                    i.serializeCause)(this.data.cause))),
                this.stack && (e.stack = this.stack),
                    e
            }
            toString() {
                return (0,
                    o.default)(this.serialize(), c, 2)
            }
        }
        r.JsonRpcError = a;
        function c(e, t) {
            if ("[Circular]" !== t)
                return t
        }
        r.EthereumProviderError = class extends a {
            constructor(e, t, r) {
                if (!function(e) {
                    return Number.isInteger(e) && e >= 1e3 && e <= 4999
                }(e))
                    throw new Error('"code" must be an integer such that: 1000 <= code <= 4999');
                super(e, t, r)
            }
        }
    }
        , {
            "./utils.cjs": 154,
            "@metamask/utils": 165,
            "fast-safe-stringify": 202
        }],
    151: [function(e, t, r) {
        "use strict";
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.errorValues = r.errorCodes = void 0,
            r.errorCodes = {
                rpc: {
                    invalidInput: -32e3,
                    resourceNotFound: -32001,
                    resourceUnavailable: -32002,
                    transactionRejected: -32003,
                    methodNotSupported: -32004,
                    limitExceeded: -32005,
                    parse: -32700,
                    invalidRequest: -32600,
                    methodNotFound: -32601,
                    invalidParams: -32602,
                    internal: -32603
                },
                provider: {
                    userRejectedRequest: 4001,
                    unauthorized: 4100,
                    unsupportedMethod: 4200,
                    disconnected: 4900,
                    chainDisconnected: 4901
                }
            },
            r.errorValues = {
                "-32700": {
                    standard: "JSON RPC 2.0",
                    message: "Invalid JSON was received by the server. An error occurred on the server while parsing the JSON text."
                },
                "-32600": {
                    standard: "JSON RPC 2.0",
                    message: "The JSON sent is not a valid Request object."
                },
                "-32601": {
                    standard: "JSON RPC 2.0",
                    message: "The method does not exist / is not available."
                },
                "-32602": {
                    standard: "JSON RPC 2.0",
                    message: "Invalid method parameter(s)."
                },
                "-32603": {
                    standard: "JSON RPC 2.0",
                    message: "Internal JSON-RPC error."
                },
                "-32000": {
                    standard: "EIP-1474",
                    message: "Invalid input."
                },
                "-32001": {
                    standard: "EIP-1474",
                    message: "Resource not found."
                },
                "-32002": {
                    standard: "EIP-1474",
                    message: "Resource unavailable."
                },
                "-32003": {
                    standard: "EIP-1474",
                    message: "Transaction rejected."
                },
                "-32004": {
                    standard: "EIP-1474",
                    message: "Method not supported."
                },
                "-32005": {
                    standard: "EIP-1474",
                    message: "Request limit exceeded."
                },
                4001: {
                    standard: "EIP-1193",
                    message: "User rejected the request."
                },
                4100: {
                    standard: "EIP-1193",
                    message: "The requested account and/or method has not been authorized by the user."
                },
                4200: {
                    standard: "EIP-1193",
                    message: "The requested method is not supported by this Ethereum provider."
                },
                4900: {
                    standard: "EIP-1193",
                    message: "The provider is disconnected from all chains."
                },
                4901: {
                    standard: "EIP-1193",
                    message: "The provider is disconnected from the specified chain."
                }
            }
    }
        , {}],
    152: [function(e, t, r) {
        "use strict";
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.providerErrors = r.rpcErrors = void 0;
        const n = e("./classes.cjs")
            , s = e("./error-constants.cjs")
            , o = e("./utils.cjs");
        function i(e, t) {
            const [r,s] = c(t);
            return new n.JsonRpcError(e,r ?? (0,
                o.getMessageFromCode)(e),s)
        }
        function a(e, t) {
            const [r,s] = c(t);
            return new n.EthereumProviderError(e,r ?? (0,
                o.getMessageFromCode)(e),s)
        }
        function c(e) {
            if (e) {
                if ("string" == typeof e)
                    return [e];
                if ("object" == typeof e && !Array.isArray(e)) {
                    const {message: t, data: r} = e;
                    if (t && "string" != typeof t)
                        throw new Error("Must specify string message.");
                    return [t ?? void 0, r]
                }
            }
            return []
        }
        r.rpcErrors = {
            parse: e => i(s.errorCodes.rpc.parse, e),
            invalidRequest: e => i(s.errorCodes.rpc.invalidRequest, e),
            invalidParams: e => i(s.errorCodes.rpc.invalidParams, e),
            methodNotFound: e => i(s.errorCodes.rpc.methodNotFound, e),
            internal: e => i(s.errorCodes.rpc.internal, e),
            server: e => {
                if (!e || "object" != typeof e || Array.isArray(e))
                    throw new Error("Ethereum RPC Server errors must provide single object argument.");
                const {code: t} = e;
                if (!Number.isInteger(t) || t > -32005 || t < -32099)
                    throw new Error('"code" must be an integer such that: -32099 <= code <= -32005');
                return i(t, e)
            }
            ,
            invalidInput: e => i(s.errorCodes.rpc.invalidInput, e),
            resourceNotFound: e => i(s.errorCodes.rpc.resourceNotFound, e),
            resourceUnavailable: e => i(s.errorCodes.rpc.resourceUnavailable, e),
            transactionRejected: e => i(s.errorCodes.rpc.transactionRejected, e),
            methodNotSupported: e => i(s.errorCodes.rpc.methodNotSupported, e),
            limitExceeded: e => i(s.errorCodes.rpc.limitExceeded, e)
        },
            r.providerErrors = {
                userRejectedRequest: e => a(s.errorCodes.provider.userRejectedRequest, e),
                unauthorized: e => a(s.errorCodes.provider.unauthorized, e),
                unsupportedMethod: e => a(s.errorCodes.provider.unsupportedMethod, e),
                disconnected: e => a(s.errorCodes.provider.disconnected, e),
                chainDisconnected: e => a(s.errorCodes.provider.chainDisconnected, e),
                custom: e => {
                    if (!e || "object" != typeof e || Array.isArray(e))
                        throw new Error("Ethereum Provider custom errors must provide single object argument.");
                    const {code: t, message: r, data: s} = e;
                    if (!r || "string" != typeof r)
                        throw new Error('"message" must be a nonempty string');
                    return new n.EthereumProviderError(t,r,s)
                }
            }
    }
        , {
            "./classes.cjs": 150,
            "./error-constants.cjs": 151,
            "./utils.cjs": 154
        }],
    153: [function(e, t, r) {
        "use strict";
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.errorCodes = r.providerErrors = r.rpcErrors = r.getMessageFromCode = r.serializeError = r.serializeCause = r.dataHasCause = r.EthereumProviderError = r.JsonRpcError = void 0;
        var n = e("./classes.cjs");
        Object.defineProperty(r, "JsonRpcError", {
            enumerable: !0,
            get: function() {
                return n.JsonRpcError
            }
        }),
            Object.defineProperty(r, "EthereumProviderError", {
                enumerable: !0,
                get: function() {
                    return n.EthereumProviderError
                }
            });
        var s = e("./utils.cjs");
        Object.defineProperty(r, "dataHasCause", {
            enumerable: !0,
            get: function() {
                return s.dataHasCause
            }
        }),
            Object.defineProperty(r, "serializeCause", {
                enumerable: !0,
                get: function() {
                    return s.serializeCause
                }
            }),
            Object.defineProperty(r, "serializeError", {
                enumerable: !0,
                get: function() {
                    return s.serializeError
                }
            }),
            Object.defineProperty(r, "getMessageFromCode", {
                enumerable: !0,
                get: function() {
                    return s.getMessageFromCode
                }
            });
        var o = e("./errors.cjs");
        Object.defineProperty(r, "rpcErrors", {
            enumerable: !0,
            get: function() {
                return o.rpcErrors
            }
        }),
            Object.defineProperty(r, "providerErrors", {
                enumerable: !0,
                get: function() {
                    return o.providerErrors
                }
            });
        var i = e("./error-constants.cjs");
        Object.defineProperty(r, "errorCodes", {
            enumerable: !0,
            get: function() {
                return i.errorCodes
            }
        })
    }
        , {
            "./classes.cjs": 150,
            "./error-constants.cjs": 151,
            "./errors.cjs": 152,
            "./utils.cjs": 154
        }],
    154: [function(e, t, r) {
        "use strict";
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.dataHasCause = r.serializeCause = r.serializeError = r.isValidCode = r.getMessageFromCode = r.JSON_RPC_SERVER_ERROR_MESSAGE = void 0;
        const n = e("@metamask/utils")
            , s = e("./error-constants.cjs")
            , o = s.errorCodes.rpc.internal
            , i = {
            code: o,
            message: a(o)
        };
        function a(e, t="Unspecified error message. This is a bug, please report it.") {
            if (c(e)) {
                const t = e.toString();
                if ((0,
                    n.hasProperty)(s.errorValues, t))
                    return s.errorValues[t].message;
                if (function(e) {
                    return e >= -32099 && e <= -32e3
                }(e))
                    return r.JSON_RPC_SERVER_ERROR_MESSAGE
            }
            return t
        }
        function c(e) {
            return Number.isInteger(e)
        }
        function u(e) {
            return Array.isArray(e) ? e.map((e => (0,
                n.isValidJson)(e) ? e : (0,
                n.isObject)(e) ? l(e) : null)) : (0,
                n.isObject)(e) ? l(e) : (0,
                n.isValidJson)(e) ? e : null
        }
        function l(e) {
            return Object.getOwnPropertyNames(e).reduce(( (t, r) => {
                    const s = e[r];
                    return (0,
                        n.isValidJson)(s) && (t[r] = s),
                        t
                }
            ), {})
        }
        r.JSON_RPC_SERVER_ERROR_MESSAGE = "Unspecified server error.",
            r.getMessageFromCode = a,
            r.isValidCode = c,
            r.serializeError = function(e, {fallbackError: t=i, shouldIncludeStack: r=!0, shouldPreserveMessage: s=!0}={}) {
                if (!(0,
                    n.isJsonRpcError)(t))
                    throw new Error("Must provide fallback error with integer number code and string message.");
                const o = function(e, t, r) {
                    if (e && "object" == typeof e && "serialize"in e && "function" == typeof e.serialize)
                        return e.serialize();
                    if ((0,
                        n.isJsonRpcError)(e))
                        return e;
                    const s = function(e) {
                        if ((0,
                            n.isObject)(e) && (0,
                            n.hasProperty)(e, "message") && "string" == typeof e.message && e.message.length > 0)
                            return e.message;
                        return
                    }(e)
                        , o = u(e)
                        , i = {
                        ...t,
                        ...r && s && {
                            message: s
                        },
                        data: {
                            cause: o
                        }
                    };
                    return i
                }(e, t, s);
                return r || delete o.stack,
                    o
            }
            ,
            r.serializeCause = u,
            r.dataHasCause = function(e) {
                return (0,
                    n.isObject)(e) && (0,
                    n.hasProperty)(e, "cause") && (0,
                    n.isObject)(e.cause)
            }
    }
        , {
            "./error-constants.cjs": 151,
            "@metamask/utils": 165
        }],
    155: [function(e, t, r) {
        arguments[4][9][0].apply(r, arguments)
    }
        , {
            "./errors.cjs": 163,
            "@metamask/superstruct": 179,
            dup: 9
        }],
    156: [function(e, t, r) {
        arguments[4][10][0].apply(r, arguments)
    }
        , {
            "./assert.cjs": 155,
            "@metamask/superstruct": 179,
            dup: 10
        }],
    157: [function(e, t, r) {
        (function(t) {
                (function() {
                        "use strict";
                        Object.defineProperty(r, "__esModule", {
                            value: !0
                        }),
                            r.createDataView = r.concatBytes = r.valueToBytes = r.base64ToBytes = r.stringToBytes = r.numberToBytes = r.signedBigIntToBytes = r.bigIntToBytes = r.hexToBytes = r.bytesToBase64 = r.bytesToString = r.bytesToNumber = r.bytesToSignedBigInt = r.bytesToBigInt = r.bytesToHex = r.assertIsBytes = r.isBytes = void 0;
                        const n = e("@scure/base")
                            , s = e("./assert.cjs")
                            , o = e("./hex.cjs")
                            , i = 48
                            , a = 58
                            , c = 87;
                        const u = function() {
                            const e = [];
                            return () => {
                                if (0 === e.length)
                                    for (let t = 0; t < 256; t++)
                                        e.push(t.toString(16).padStart(2, "0"));
                                return e
                            }
                        }();
                        function l(e) {
                            return e instanceof Uint8Array
                        }
                        function d(e) {
                            (0,
                                s.assert)(l(e), "Value must be a Uint8Array.")
                        }
                        function f(e) {
                            if (d(e),
                            0 === e.length)
                                return "0x";
                            const t = u()
                                , r = new Array(e.length);
                            for (let n = 0; n < e.length; n++)
                                r[n] = t[e[n]];
                            return (0,
                                o.add0x)(r.join(""))
                        }
                        function p(e) {
                            d(e);
                            const t = f(e);
                            return BigInt(t)
                        }
                        function h(e) {
                            if ("0x" === e?.toLowerCase?.())
                                return new Uint8Array;
                            (0,
                                o.assertIsHexString)(e);
                            const t = (0,
                                o.remove0x)(e).toLowerCase()
                                , r = t.length % 2 == 0 ? t : `0${t}`
                                , n = new Uint8Array(r.length / 2);
                            for (let e = 0; e < n.length; e++) {
                                const t = r.charCodeAt(2 * e)
                                    , s = r.charCodeAt(2 * e + 1)
                                    , o = t - (t < a ? i : c)
                                    , u = s - (s < a ? i : c);
                                n[e] = 16 * o + u
                            }
                            return n
                        }
                        function g(e) {
                            (0,
                                s.assert)("bigint" == typeof e, "Value must be a bigint."),
                                (0,
                                    s.assert)(e >= BigInt(0), "Value must be a non-negative bigint.");
                            return h(e.toString(16))
                        }
                        function m(e) {
                            (0,
                                s.assert)("number" == typeof e, "Value must be a number."),
                                (0,
                                    s.assert)(e >= 0, "Value must be a non-negative number."),
                                (0,
                                    s.assert)(Number.isSafeInteger(e), "Value is not a safe integer. Use `bigIntToBytes` instead.");
                            return h(e.toString(16))
                        }
                        function b(e) {
                            return (0,
                                s.assert)("string" == typeof e, "Value must be a string."),
                                (new TextEncoder).encode(e)
                        }
                        function y(e) {
                            if ("bigint" == typeof e)
                                return g(e);
                            if ("number" == typeof e)
                                return m(e);
                            if ("string" == typeof e)
                                return e.startsWith("0x") ? h(e) : b(e);
                            if (l(e))
                                return e;
                            throw new TypeError(`Unsupported value type: "${typeof e}".`)
                        }
                        r.isBytes = l,
                            r.assertIsBytes = d,
                            r.bytesToHex = f,
                            r.bytesToBigInt = p,
                            r.bytesToSignedBigInt = function(e) {
                                d(e);
                                let t = BigInt(0);
                                for (const r of e)
                                    t = (t << BigInt(8)) + BigInt(r);
                                return BigInt.asIntN(8 * e.length, t)
                            }
                            ,
                            r.bytesToNumber = function(e) {
                                d(e);
                                const t = p(e);
                                return (0,
                                    s.assert)(t <= BigInt(Number.MAX_SAFE_INTEGER), "Number is not a safe integer. Use `bytesToBigInt` instead."),
                                    Number(t)
                            }
                            ,
                            r.bytesToString = function(e) {
                                return d(e),
                                    (new TextDecoder).decode(e)
                            }
                            ,
                            r.bytesToBase64 = function(e) {
                                return d(e),
                                    n.base64.encode(e)
                            }
                            ,
                            r.hexToBytes = h,
                            r.bigIntToBytes = g,
                            r.signedBigIntToBytes = function(e, t) {
                                (0,
                                    s.assert)("bigint" == typeof e, "Value must be a bigint."),
                                    (0,
                                        s.assert)("number" == typeof t, "Byte length must be a number."),
                                    (0,
                                        s.assert)(t > 0, "Byte length must be greater than 0."),
                                    (0,
                                        s.assert)(function(e, t) {
                                        (0,
                                            s.assert)(t > 0);
                                        const r = e >> BigInt(31);
                                        return !((~e & r) + (e & ~r) >> BigInt(8 * t - 1))
                                    }(e, t), "Byte length is too small to represent the given value.");
                                let r = e;
                                const n = new Uint8Array(t);
                                for (let e = 0; e < n.length; e++)
                                    n[e] = Number(BigInt.asUintN(8, r)),
                                        r >>= BigInt(8);
                                return n.reverse()
                            }
                            ,
                            r.numberToBytes = m,
                            r.stringToBytes = b,
                            r.base64ToBytes = function(e) {
                                return (0,
                                    s.assert)("string" == typeof e, "Value must be a string."),
                                    n.base64.decode(e)
                            }
                            ,
                            r.valueToBytes = y,
                            r.concatBytes = function(e) {
                                const t = new Array(e.length);
                                let r = 0;
                                for (let n = 0; n < e.length; n++) {
                                    const s = y(e[n]);
                                    t[n] = s,
                                        r += s.length
                                }
                                const n = new Uint8Array(r);
                                for (let e = 0, r = 0; e < t.length; e++)
                                    n.set(t[e], r),
                                        r += t[e].length;
                                return n
                            }
                            ,
                            r.createDataView = function(e) {
                                if (void 0 !== t && e instanceof t) {
                                    const t = e.buffer.slice(e.byteOffset, e.byteOffset + e.byteLength);
                                    return new DataView(t)
                                }
                                return new DataView(e.buffer,e.byteOffset,e.byteLength)
                            }
                    }
                ).call(this)
            }
        ).call(this, e("buffer").Buffer)
    }
        , {
            "./assert.cjs": 155,
            "./hex.cjs": 164,
            "@scure/base": 191,
            buffer: 195
        }],
    158: [function(e, t, r) {
        arguments[4][12][0].apply(r, arguments)
    }
        , {
            "./superstruct.cjs": 173,
            "@metamask/superstruct": 179,
            dup: 12
        }],
    159: [function(e, t, r) {
        arguments[4][13][0].apply(r, arguments)
    }
        , {
            "./base64.cjs": 156,
            "@metamask/superstruct": 179,
            dup: 13
        }],
    160: [function(e, t, r) {
        arguments[4][14][0].apply(r, arguments)
    }
        , {
            "./assert.cjs": 155,
            "./bytes.cjs": 157,
            "./hex.cjs": 164,
            "@metamask/superstruct": 179,
            dup: 14
        }],
    161: [function(e, t, r) {
        arguments[4][15][0].apply(r, arguments)
    }
        , {
            dup: 15
        }],
    162: [function(e, t, r) {
        arguments[4][16][0].apply(r, arguments)
    }
        , {
            dup: 16
        }],
    163: [function(e, t, r) {
        arguments[4][17][0].apply(r, arguments)
    }
        , {
            "./misc.cjs": 169,
            dup: 17,
            "pony-cause": 208
        }],
    164: [function(e, t, r) {
        arguments[4][18][0].apply(r, arguments)
    }
        , {
            "./assert.cjs": 155,
            "./bytes.cjs": 157,
            "@metamask/superstruct": 179,
            "@noble/hashes/sha3": 189,
            dup: 18
        }],
    165: [function(e, t, r) {
        arguments[4][19][0].apply(r, arguments)
    }
        , {
            "./assert.cjs": 155,
            "./base64.cjs": 156,
            "./bytes.cjs": 157,
            "./caip-types.cjs": 158,
            "./checksum.cjs": 159,
            "./coercers.cjs": 160,
            "./collections.cjs": 161,
            "./encryption-types.cjs": 162,
            "./errors.cjs": 163,
            "./hex.cjs": 164,
            "./json.cjs": 166,
            "./keyring.cjs": 167,
            "./logging.cjs": 168,
            "./misc.cjs": 169,
            "./number.cjs": 170,
            "./opaque.cjs": 171,
            "./promise.cjs": 172,
            "./superstruct.cjs": 173,
            "./time.cjs": 174,
            "./transaction-types.cjs": 175,
            "./versions.cjs": 176,
            dup: 19
        }],
    166: [function(e, t, r) {
        arguments[4][20][0].apply(r, arguments)
    }
        , {
            "./assert.cjs": 155,
            "./misc.cjs": 169,
            "@metamask/superstruct": 179,
            dup: 20
        }],
    167: [function(e, t, r) {
        arguments[4][21][0].apply(r, arguments)
    }
        , {
            dup: 21
        }],
    168: [function(e, t, r) {
        arguments[4][22][0].apply(r, arguments)
    }
        , {
            debug: 197,
            dup: 22
        }],
    169: [function(e, t, r) {
        arguments[4][23][0].apply(r, arguments)
    }
        , {
            dup: 23
        }],
    170: [function(e, t, r) {
        arguments[4][24][0].apply(r, arguments)
    }
        , {
            "./assert.cjs": 155,
            "./hex.cjs": 164,
            dup: 24
        }],
    171: [function(e, t, r) {
        arguments[4][25][0].apply(r, arguments)
    }
        , {
            dup: 25
        }],
    172: [function(e, t, r) {
        arguments[4][26][0].apply(r, arguments)
    }
        , {
            dup: 26
        }],
    173: [function(e, t, r) {
        arguments[4][27][0].apply(r, arguments)
    }
        , {
            "@metamask/superstruct": 179,
            dup: 27
        }],
    174: [function(e, t, r) {
        arguments[4][28][0].apply(r, arguments)
    }
        , {
            dup: 28
        }],
    175: [function(e, t, r) {
        arguments[4][29][0].apply(r, arguments)
    }
        , {
            dup: 29
        }],
    176: [function(e, t, r) {
        arguments[4][30][0].apply(r, arguments)
    }
        , {
            "./assert.cjs": 155,
            "@metamask/superstruct": 179,
            dup: 30,
            semver: 255
        }],
    177: [function(e, t, r) {
        "use strict";
        Object.defineProperty(r, "__esModule", {
            value: !0
        });
        const n = e("events");
        function s(e, t, r) {
            try {
                Reflect.apply(e, t, r)
            } catch (e) {
                setTimeout(( () => {
                        throw e
                    }
                ))
            }
        }
        class o extends n.EventEmitter {
            emit(e, ...t) {
                let r = "error" === e;
                const n = this._events;
                if (void 0 !== n)
                    r = r && void 0 === n.error;
                else if (!r)
                    return !1;
                if (r) {
                    let e;
                    if (t.length > 0 && ([e] = t),
                    e instanceof Error)
                        throw e;
                    const r = new Error("Unhandled error." + (e ? ` (${e.message})` : ""));
                    throw r.context = e,
                        r
                }
                const o = n[e];
                if (void 0 === o)
                    return !1;
                if ("function" == typeof o)
                    s(o, this, t);
                else {
                    const e = o.length
                        , r = function(e) {
                        const t = e.length
                            , r = new Array(t);
                        for (let n = 0; n < t; n += 1)
                            r[n] = e[n];
                        return r
                    }(o);
                    for (let n = 0; n < e; n += 1)
                        s(r[n], this, t)
                }
                return !0
            }
        }
        r.default = o
    }
        , {
            events: 200
        }],
    178: [function(e, t, r) {
        "use strict";
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.StructError = void 0;
        class n extends TypeError {
            constructor(e, t) {
                let r;
                const {message: n, explanation: s, ...o} = e
                    , {path: i} = e
                    , a = 0 === i.length ? n : `At path: ${i.join(".")} -- ${n}`;
                super(s ?? a),
                null != s && (this.cause = a),
                    Object.assign(this, o),
                    this.name = this.constructor.name,
                    this.failures = () => r ?? (r = [e, ...t()])
            }
        }
        r.StructError = n
    }
        , {}],
    179: [function(e, t, r) {
        "use strict";
        var n = this && this.__createBinding || (Object.create ? function(e, t, r, n) {
                        void 0 === n && (n = r);
                        var s = Object.getOwnPropertyDescriptor(t, r);
                        s && !("get"in s ? !t.__esModule : s.writable || s.configurable) || (s = {
                            enumerable: !0,
                            get: function() {
                                return t[r]
                            }
                        }),
                            Object.defineProperty(e, n, s)
                    }
                    : function(e, t, r, n) {
                        void 0 === n && (n = r),
                            e[n] = t[r]
                    }
            )
            , s = this && this.__exportStar || function(e, t) {
                for (var r in e)
                    "default" === r || Object.prototype.hasOwnProperty.call(t, r) || n(t, e, r)
            }
        ;
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            s(e("./error.cjs"), r),
            s(e("./struct.cjs"), r),
            s(e("./structs/coercions.cjs"), r),
            s(e("./structs/refinements.cjs"), r),
            s(e("./structs/types.cjs"), r),
            s(e("./structs/utilities.cjs"), r)
    }
        , {
            "./error.cjs": 178,
            "./struct.cjs": 180,
            "./structs/coercions.cjs": 181,
            "./structs/refinements.cjs": 182,
            "./structs/types.cjs": 183,
            "./structs/utilities.cjs": 184
        }],
    180: [function(e, t, r) {
        "use strict";
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.validate = r.is = r.mask = r.create = r.assert = r.Struct = void 0;
        const n = e("./error.cjs")
            , s = e("./utils.cjs");
        function o(e, t, r) {
            const n = u(e, t, {
                message: r
            });
            if (n[0])
                throw n[0]
        }
        function i(e, t, r) {
            const n = u(e, t, {
                coerce: !0,
                message: r
            });
            if (n[0])
                throw n[0];
            return n[1]
        }
        function a(e, t, r) {
            const n = u(e, t, {
                coerce: !0,
                mask: !0,
                message: r
            });
            if (n[0])
                throw n[0];
            return n[1]
        }
        function c(e, t) {
            return !u(e, t)[0]
        }
        function u(e, t, r={}) {
            const o = (0,
                s.run)(e, t, r)
                , i = (0,
                s.shiftIterator)(o);
            if (i[0]) {
                return [new n.StructError(i[0],(function*() {
                        for (const e of o)
                            e[0] && (yield e[0])
                    }
                )), void 0]
            }
            return [void 0, i[1]]
        }
        r.Struct = class {
            constructor(e) {
                const {type: t, schema: r, validator: n, refiner: o, coercer: i=(e => e), entries: a=function*() {}
                } = e;
                this.type = t,
                    this.schema = r,
                    this.entries = a,
                    this.coercer = i,
                    this.validator = n ? (e, t) => {
                            const r = n(e, t);
                            return (0,
                                s.toFailures)(r, t, this, e)
                        }
                        : () => [],
                    this.refiner = o ? (e, t) => {
                            const r = o(e, t);
                            return (0,
                                s.toFailures)(r, t, this, e)
                        }
                        : () => []
            }
            assert(e, t) {
                return o(e, this, t)
            }
            create(e, t) {
                return i(e, this, t)
            }
            is(e) {
                return c(e, this)
            }
            mask(e, t) {
                return a(e, this, t)
            }
            validate(e, t={}) {
                return u(e, this, t)
            }
        }
            ,
            r.assert = o,
            r.create = i,
            r.mask = a,
            r.is = c,
            r.validate = u
    }
        , {
            "./error.cjs": 178,
            "./utils.cjs": 185
        }],
    181: [function(e, t, r) {
        "use strict";
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.trimmed = r.defaulted = r.coerce = void 0;
        const n = e("../struct.cjs")
            , s = e("../utils.cjs")
            , o = e("./types.cjs");
        function i(e, t, r) {
            return new n.Struct({
                ...e,
                coercer: (s, o) => (0,
                    n.is)(s, t) ? e.coercer(r(s, o), o) : e.coercer(s, o)
            })
        }
        r.coerce = i,
            r.defaulted = function(e, t, r={}) {
                return i(e, (0,
                    o.unknown)(), (e => {
                        const n = "function" == typeof t ? t() : t;
                        if (void 0 === e)
                            return n;
                        if (!r.strict && (0,
                            s.isPlainObject)(e) && (0,
                            s.isPlainObject)(n)) {
                            const t = {
                                ...e
                            };
                            let r = !1;
                            for (const e in n)
                                void 0 === t[e] && (t[e] = n[e],
                                    r = !0);
                            if (r)
                                return t
                        }
                        return e
                    }
                ))
            }
            ,
            r.trimmed = function(e) {
                return i(e, (0,
                    o.string)(), (e => e.trim()))
            }
    }
        , {
            "../struct.cjs": 180,
            "../utils.cjs": 185,
            "./types.cjs": 183
        }],
    182: [function(e, t, r) {
        "use strict";
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.refine = r.size = r.pattern = r.nonempty = r.min = r.max = r.empty = void 0;
        const n = e("../struct.cjs")
            , s = e("../utils.cjs");
        function o(e) {
            return e instanceof Map || e instanceof Set ? e.size : e.length
        }
        function i(e, t, r) {
            return new n.Struct({
                ...e,
                *refiner(n, o) {
                    yield*e.refiner(n, o);
                    const i = r(n, o)
                        , a = (0,
                        s.toFailures)(i, o, e, n);
                    for (const e of a)
                        yield{
                            ...e,
                            refinement: t
                        }
                }
            })
        }
        r.empty = function(e) {
            return i(e, "empty", (t => {
                    const r = o(t);
                    return 0 === r || `Expected an empty ${e.type} but received one with a size of \`${r}\``
                }
            ))
        }
            ,
            r.max = function(e, t, r={}) {
                const {exclusive: n} = r;
                return i(e, "max", (r => n ? r < t : r <= t || `Expected a ${e.type} less than ${n ? "" : "or equal to "}${t} but received \`${r}\``))
            }
            ,
            r.min = function(e, t, r={}) {
                const {exclusive: n} = r;
                return i(e, "min", (r => n ? r > t : r >= t || `Expected a ${e.type} greater than ${n ? "" : "or equal to "}${t} but received \`${r}\``))
            }
            ,
            r.nonempty = function(e) {
                return i(e, "nonempty", (t => o(t) > 0 || `Expected a nonempty ${e.type} but received an empty one`))
            }
            ,
            r.pattern = function(e, t) {
                return i(e, "pattern", (r => t.test(r) || `Expected a ${e.type} matching \`/${t.source}/\` but received "${r}"`))
            }
            ,
            r.size = function(e, t, r=t) {
                const n = `Expected a ${e.type}`
                    , s = t === r ? `of \`${t}\`` : `between \`${t}\` and \`${r}\``;
                return i(e, "size", (e => {
                        if ("number" == typeof e || e instanceof Date)
                            return t <= e && e <= r || `${n} ${s} but received \`${e}\``;
                        if (e instanceof Map || e instanceof Set) {
                            const {size: o} = e;
                            return t <= o && o <= r || `${n} with a size ${s} but received one with a size of \`${o}\``
                        }
                        const {length: o} = e;
                        return t <= o && o <= r || `${n} with a length ${s} but received one with a length of \`${o}\``
                    }
                ))
            }
            ,
            r.refine = i
    }
        , {
            "../struct.cjs": 180,
            "../utils.cjs": 185
        }],
    183: [function(e, t, r) {
        "use strict";
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.unknown = r.union = r.type = r.tuple = r.string = r.set = r.regexp = r.record = r.optional = r.object = r.number = r.nullable = r.never = r.map = r.literal = r.intersection = r.integer = r.instance = r.func = r.enums = r.date = r.boolean = r.bigint = r.array = r.any = void 0;
        const n = e("../struct.cjs")
            , s = e("../utils.cjs")
            , o = e("./utilities.cjs");
        function i() {
            return (0,
                o.define)("never", ( () => !1))
        }
        r.any = function() {
            return (0,
                o.define)("any", ( () => !0))
        }
            ,
            r.array = function(e) {
                return new n.Struct({
                    type: "array",
                    schema: e,
                    *entries(t) {
                        if (e && Array.isArray(t))
                            for (const [r,n] of t.entries())
                                yield[r, n, e]
                    },
                    coercer: e => Array.isArray(e) ? e.slice() : e,
                    validator: e => Array.isArray(e) || `Expected an array value, but received: ${(0,
                        s.print)(e)}`
                })
            }
            ,
            r.bigint = function() {
                return (0,
                    o.define)("bigint", (e => "bigint" == typeof e))
            }
            ,
            r.boolean = function() {
                return (0,
                    o.define)("boolean", (e => "boolean" == typeof e))
            }
            ,
            r.date = function() {
                return (0,
                    o.define)("date", (e => e instanceof Date && !isNaN(e.getTime()) || `Expected a valid \`Date\` object, but received: ${(0,
                    s.print)(e)}`))
            }
            ,
            r.enums = function(e) {
                const t = {}
                    , r = e.map((e => (0,
                    s.print)(e))).join();
                for (const r of e)
                    t[r] = r;
                return new n.Struct({
                    type: "enums",
                    schema: t,
                    validator: t => e.includes(t) || `Expected one of \`${r}\`, but received: ${(0,
                        s.print)(t)}`
                })
            }
            ,
            r.func = function() {
                return (0,
                    o.define)("func", (e => "function" == typeof e || `Expected a function, but received: ${(0,
                    s.print)(e)}`))
            }
            ,
            r.instance = function(e) {
                return (0,
                    o.define)("instance", (t => t instanceof e || `Expected a \`${e.name}\` instance, but received: ${(0,
                    s.print)(t)}`))
            }
            ,
            r.integer = function() {
                return (0,
                    o.define)("integer", (e => "number" == typeof e && !isNaN(e) && Number.isInteger(e) || `Expected an integer, but received: ${(0,
                    s.print)(e)}`))
            }
            ,
            r.intersection = function(e) {
                return new n.Struct({
                    type: "intersection",
                    schema: null,
                    *entries(t, r) {
                        for (const {entries: n} of e)
                            yield*n(t, r)
                    },
                    *validator(t, r) {
                        for (const {validator: n} of e)
                            yield*n(t, r)
                    },
                    *refiner(t, r) {
                        for (const {refiner: n} of e)
                            yield*n(t, r)
                    }
                })
            }
            ,
            r.literal = function(e) {
                const t = (0,
                    s.print)(e)
                    , r = typeof e;
                return new n.Struct({
                    type: "literal",
                    schema: "string" === r || "number" === r || "boolean" === r ? e : null,
                    validator: r => r === e || `Expected the literal \`${t}\`, but received: ${(0,
                        s.print)(r)}`
                })
            }
            ,
            r.map = function(e, t) {
                return new n.Struct({
                    type: "map",
                    schema: null,
                    *entries(r) {
                        if (e && t && r instanceof Map)
                            for (const [n,s] of r.entries())
                                yield[n, n, e],
                                    yield[n, s, t]
                    },
                    coercer: e => e instanceof Map ? new Map(e) : e,
                    validator: e => e instanceof Map || `Expected a \`Map\` object, but received: ${(0,
                        s.print)(e)}`
                })
            }
            ,
            r.never = i,
            r.nullable = function(e) {
                return new n.Struct({
                    ...e,
                    validator: (t, r) => null === t || e.validator(t, r),
                    refiner: (t, r) => null === t || e.refiner(t, r)
                })
            }
            ,
            r.number = function() {
                return (0,
                    o.define)("number", (e => "number" == typeof e && !isNaN(e) || `Expected a number, but received: ${(0,
                    s.print)(e)}`))
            }
            ,
            r.object = function(e) {
                const t = e ? Object.keys(e) : []
                    , r = i();
                return new n.Struct({
                    type: "object",
                    schema: e ?? null,
                    *entries(n) {
                        if (e && (0,
                            s.isObject)(n)) {
                            const s = new Set(Object.keys(n));
                            for (const r of t)
                                s.delete(r),
                                    yield[r, n[r], e[r]];
                            for (const e of s)
                                yield[e, n[e], r]
                        }
                    },
                    validator: e => (0,
                        s.isObject)(e) || `Expected an object, but received: ${(0,
                        s.print)(e)}`,
                    coercer: e => (0,
                        s.isObject)(e) ? {
                        ...e
                    } : e
                })
            }
            ,
            r.optional = function(e) {
                return new n.Struct({
                    ...e,
                    validator: (t, r) => void 0 === t || e.validator(t, r),
                    refiner: (t, r) => void 0 === t || e.refiner(t, r)
                })
            }
            ,
            r.record = function(e, t) {
                return new n.Struct({
                    type: "record",
                    schema: null,
                    *entries(r) {
                        if ((0,
                            s.isObject)(r))
                            for (const n in r) {
                                const s = r[n];
                                yield[n, n, e],
                                    yield[n, s, t]
                            }
                    },
                    validator: e => (0,
                        s.isObject)(e) || `Expected an object, but received: ${(0,
                        s.print)(e)}`
                })
            }
            ,
            r.regexp = function() {
                return (0,
                    o.define)("regexp", (e => e instanceof RegExp))
            }
            ,
            r.set = function(e) {
                return new n.Struct({
                    type: "set",
                    schema: null,
                    *entries(t) {
                        if (e && t instanceof Set)
                            for (const r of t)
                                yield[r, r, e]
                    },
                    coercer: e => e instanceof Set ? new Set(e) : e,
                    validator: e => e instanceof Set || `Expected a \`Set\` object, but received: ${(0,
                        s.print)(e)}`
                })
            }
            ,
            r.string = function() {
                return (0,
                    o.define)("string", (e => "string" == typeof e || `Expected a string, but received: ${(0,
                    s.print)(e)}`))
            }
            ,
            r.tuple = function(e) {
                const t = i();
                return new n.Struct({
                    type: "tuple",
                    schema: null,
                    *entries(r) {
                        if (Array.isArray(r)) {
                            const n = Math.max(e.length, r.length);
                            for (let s = 0; s < n; s++)
                                yield[s, r[s], e[s] || t]
                        }
                    },
                    validator: e => Array.isArray(e) || `Expected an array, but received: ${(0,
                        s.print)(e)}`
                })
            }
            ,
            r.type = function(e) {
                const t = Object.keys(e);
                return new n.Struct({
                    type: "type",
                    schema: e,
                    *entries(r) {
                        if ((0,
                            s.isObject)(r))
                            for (const n of t)
                                yield[n, r[n], e[n]]
                    },
                    validator: e => (0,
                        s.isObject)(e) || `Expected an object, but received: ${(0,
                        s.print)(e)}`,
                    coercer: e => (0,
                        s.isObject)(e) ? {
                        ...e
                    } : e
                })
            }
            ,
            r.union = function(e) {
                const t = e.map((e => e.type)).join(" | ");
                return new n.Struct({
                    type: "union",
                    schema: null,
                    coercer(t) {
                        for (const r of e) {
                            const [e,n] = r.validate(t, {
                                coerce: !0
                            });
                            if (!e)
                                return n
                        }
                        return t
                    },
                    validator(r, n) {
                        const o = [];
                        for (const t of e) {
                            const [...e] = (0,
                                s.run)(r, t, n)
                                , [i] = e;
                            if (!i?.[0])
                                return [];
                            for (const [t] of e)
                                t && o.push(t)
                        }
                        return [`Expected the value to satisfy a union of \`${t}\`, but received: ${(0,
                            s.print)(r)}`, ...o]
                    }
                })
            }
            ,
            r.unknown = function() {
                return (0,
                    o.define)("unknown", ( () => !0))
            }
    }
        , {
            "../struct.cjs": 180,
            "../utils.cjs": 185,
            "./utilities.cjs": 184
        }],
    184: [function(e, t, r) {
        "use strict";
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.pick = r.partial = r.omit = r.lazy = r.dynamic = r.deprecated = r.define = r.assign = void 0;
        const n = e("../struct.cjs")
            , s = e("./types.cjs");
        r.assign = function(...e) {
            const t = "type" === e[0]?.type
                , r = e.map(( ({schema: e}) => e))
                , n = Object.assign({}, ...r);
            return t ? (0,
                s.type)(n) : (0,
                s.object)(n)
        }
            ,
            r.define = function(e, t) {
                return new n.Struct({
                    type: e,
                    schema: null,
                    validator: t
                })
            }
            ,
            r.deprecated = function(e, t) {
                return new n.Struct({
                    ...e,
                    refiner: (t, r) => void 0 === t || e.refiner(t, r),
                    validator: (r, n) => void 0 === r || (t(r, n),
                        e.validator(r, n))
                })
            }
            ,
            r.dynamic = function(e) {
                return new n.Struct({
                    type: "dynamic",
                    schema: null,
                    *entries(t, r) {
                        const n = e(t, r);
                        yield*n.entries(t, r)
                    },
                    validator: (t, r) => e(t, r).validator(t, r),
                    coercer: (t, r) => e(t, r).coercer(t, r),
                    refiner: (t, r) => e(t, r).refiner(t, r)
                })
            }
            ,
            r.lazy = function(e) {
                let t;
                return new n.Struct({
                    type: "lazy",
                    schema: null,
                    *entries(r, n) {
                        t ?? (t = e()),
                            yield*t.entries(r, n)
                    },
                    validator: (r, n) => (t ?? (t = e()),
                        t.validator(r, n)),
                    coercer: (r, n) => (t ?? (t = e()),
                        t.coercer(r, n)),
                    refiner: (r, n) => (t ?? (t = e()),
                        t.refiner(r, n))
                })
            }
            ,
            r.omit = function(e, t) {
                const {schema: r} = e
                    , n = {
                    ...r
                };
                for (const e of t)
                    delete n[e];
                return "type" === e.type ? (0,
                    s.type)(n) : (0,
                    s.object)(n)
            }
            ,
            r.partial = function(e) {
                const t = e instanceof n.Struct
                    , r = t ? {
                    ...e.schema
                } : {
                    ...e
                };
                for (const e in r)
                    r[e] = (0,
                        s.optional)(r[e]);
                return t && "type" === e.type ? (0,
                    s.type)(r) : (0,
                    s.object)(r)
            }
            ,
            r.pick = function(e, t) {
                const {schema: r} = e
                    , n = {};
                for (const e of t)
                    n[e] = r[e];
                return "type" === e.type ? (0,
                    s.type)(n) : (0,
                    s.object)(n)
            }
    }
        , {
            "../struct.cjs": 180,
            "./types.cjs": 183
        }],
    185: [function(e, t, r) {
        "use strict";
        function n(e) {
            return "object" == typeof e && null !== e
        }
        function s(e) {
            return "symbol" == typeof e ? e.toString() : "string" == typeof e ? JSON.stringify(e) : `${e}`
        }
        function o(e, t, r, n) {
            if (!0 === e)
                return;
            !1 === e ? e = {} : "string" == typeof e && (e = {
                message: e
            });
            const {path: o, branch: i} = t
                , {type: a} = r
                , {refinement: c, message: u=`Expected a value of type \`${a}\`${c ? ` with refinement \`${c}\`` : ""}, but received: \`${s(n)}\``} = e;
            return {
                value: n,
                type: a,
                refinement: c,
                key: o[o.length - 1],
                path: o,
                branch: i,
                ...e,
                message: u
            }
        }
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.run = r.toFailures = r.toFailure = r.shiftIterator = r.print = r.isPlainObject = r.isObject = void 0,
            r.isObject = n,
            r.isPlainObject = function(e) {
                if ("[object Object]" !== Object.prototype.toString.call(e))
                    return !1;
                const t = Object.getPrototypeOf(e);
                return null === t || t === Object.prototype
            }
            ,
            r.print = s,
            r.shiftIterator = function(e) {
                const {done: t, value: r} = e.next();
                return t ? void 0 : r
            }
            ,
            r.toFailure = o,
            r.toFailures = function*(e, t, r, s) {
                (function(e) {
                        return n(e) && "function" == typeof e[Symbol.iterator]
                    }
                )(e) || (e = [e]);
                for (const n of e) {
                    const e = o(n, t, r, s);
                    e && (yield e)
                }
            }
            ,
            r.run = function *e(t, r, s={}) {
                const {path: o=[], branch: i=[t], coerce: a=!1, mask: c=!1} = s
                    , u = {
                    path: o,
                    branch: i
                };
                if (a && (t = r.coercer(t, u),
                c && "type" !== r.type && n(r.schema) && n(t) && !Array.isArray(t)))
                    for (const e in t)
                        void 0 === r.schema[e] && delete t[e];
                let l = "valid";
                for (const e of r.validator(t, u))
                    e.explanation = s.message,
                        l = "not_valid",
                        yield[e, void 0];
                for (let[d,f,p] of r.entries(t, u)) {
                    const r = e(f, p, {
                        path: void 0 === d ? o : [...o, d],
                        branch: void 0 === d ? i : [...i, f],
                        coerce: a,
                        mask: c,
                        message: s.message
                    });
                    for (const e of r)
                        e[0] ? (l = null === e[0].refinement || void 0 === e[0].refinement ? "not_valid" : "not_refined",
                            yield[e[0], void 0]) : a && (f = e[1],
                            void 0 === d ? t = f : t instanceof Map ? t.set(d, f) : t instanceof Set ? t.add(f) : n(t) && (void 0 !== f || d in t) && (t[d] = f))
                }
                if ("not_valid" !== l)
                    for (const e of r.refiner(t, u))
                        e.explanation = s.message,
                            l = "not_refined",
                            yield[e, void 0];
                "valid" === l && (yield[void 0, t])
            }
    }
        , {}],
    186: [function(e, t, r) {
        "use strict";
        function n(e) {
            if (!Number.isSafeInteger(e) || e < 0)
                throw new Error(`positive integer expected, not ${e}`)
        }
        function s(e) {
            if ("boolean" != typeof e)
                throw new Error(`boolean expected, not ${e}`)
        }
        function o(e) {
            return e instanceof Uint8Array || null != e && "object" == typeof e && "Uint8Array" === e.constructor.name
        }
        function i(e, ...t) {
            if (!o(e))
                throw new Error("Uint8Array expected");
            if (t.length > 0 && !t.includes(e.length))
                throw new Error(`Uint8Array expected of length ${t}, not of length=${e.length}`)
        }
        function a(e) {
            if ("function" != typeof e || "function" != typeof e.create)
                throw new Error("Hash should be wrapped by utils.wrapConstructor");
            n(e.outputLen),
                n(e.blockLen)
        }
        function c(e, t=!0) {
            if (e.destroyed)
                throw new Error("Hash instance has been destroyed");
            if (t && e.finished)
                throw new Error("Hash#digest() has already been called")
        }
        function u(e, t) {
            i(e);
            const r = t.outputLen;
            if (e.length < r)
                throw new Error(`digestInto() expects output buffer of length at least ${r}`)
        }
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.isBytes = o,
            r.number = n,
            r.bool = s,
            r.bytes = i,
            r.hash = a,
            r.exists = c,
            r.output = u;
        const l = {
            number: n,
            bool: s,
            bytes: i,
            hash: a,
            exists: c,
            output: u
        };
        r.default = l
    }
        , {}],
    187: [function(e, t, r) {
        "use strict";
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.add5L = r.add5H = r.add4H = r.add4L = r.add3H = r.add3L = r.rotlBL = r.rotlBH = r.rotlSL = r.rotlSH = r.rotr32L = r.rotr32H = r.rotrBL = r.rotrBH = r.rotrSL = r.rotrSH = r.shrSL = r.shrSH = r.toBig = void 0,
            r.fromBig = o,
            r.split = i,
            r.add = v;
        const n = BigInt(2 ** 32 - 1)
            , s = BigInt(32);
        function o(e, t=!1) {
            return t ? {
                h: Number(e & n),
                l: Number(e >> s & n)
            } : {
                h: 0 | Number(e >> s & n),
                l: 0 | Number(e & n)
            }
        }
        function i(e, t=!1) {
            let r = new Uint32Array(e.length)
                , n = new Uint32Array(e.length);
            for (let s = 0; s < e.length; s++) {
                const {h: i, l: a} = o(e[s], t);
                [r[s],n[s]] = [i, a]
            }
            return [r, n]
        }
        const a = (e, t) => BigInt(e >>> 0) << s | BigInt(t >>> 0);
        r.toBig = a;
        const c = (e, t, r) => e >>> r;
        r.shrSH = c;
        const u = (e, t, r) => e << 32 - r | t >>> r;
        r.shrSL = u;
        const l = (e, t, r) => e >>> r | t << 32 - r;
        r.rotrSH = l;
        const d = (e, t, r) => e << 32 - r | t >>> r;
        r.rotrSL = d;
        const f = (e, t, r) => e << 64 - r | t >>> r - 32;
        r.rotrBH = f;
        const p = (e, t, r) => e >>> r - 32 | t << 64 - r;
        r.rotrBL = p;
        const h = (e, t) => t;
        r.rotr32H = h;
        const g = (e, t) => e;
        r.rotr32L = g;
        const m = (e, t, r) => e << r | t >>> 32 - r;
        r.rotlSH = m;
        const b = (e, t, r) => t << r | e >>> 32 - r;
        r.rotlSL = b;
        const y = (e, t, r) => t << r - 32 | e >>> 64 - r;
        r.rotlBH = y;
        const w = (e, t, r) => e << r - 32 | t >>> 64 - r;
        function v(e, t, r, n) {
            const s = (t >>> 0) + (n >>> 0);
            return {
                h: e + r + (s / 2 ** 32 | 0) | 0,
                l: 0 | s
            }
        }
        r.rotlBL = w;
        const _ = (e, t, r) => (e >>> 0) + (t >>> 0) + (r >>> 0);
        r.add3L = _;
        const E = (e, t, r, n) => t + r + n + (e / 2 ** 32 | 0) | 0;
        r.add3H = E;
        const S = (e, t, r, n) => (e >>> 0) + (t >>> 0) + (r >>> 0) + (n >>> 0);
        r.add4L = S;
        const j = (e, t, r, n, s) => t + r + n + s + (e / 2 ** 32 | 0) | 0;
        r.add4H = j;
        const R = (e, t, r, n, s) => (e >>> 0) + (t >>> 0) + (r >>> 0) + (n >>> 0) + (s >>> 0);
        r.add5L = R;
        const I = (e, t, r, n, s, o) => t + r + n + s + o + (e / 2 ** 32 | 0) | 0;
        r.add5H = I;
        const A = {
            fromBig: o,
            split: i,
            toBig: a,
            shrSH: c,
            shrSL: u,
            rotrSH: l,
            rotrSL: d,
            rotrBH: f,
            rotrBL: p,
            rotr32H: h,
            rotr32L: g,
            rotlSH: m,
            rotlSL: b,
            rotlBH: y,
            rotlBL: w,
            add: v,
            add3L: _,
            add3H: E,
            add4L: S,
            add4H: j,
            add5H: I,
            add5L: R
        };
        r.default = A
    }
        , {}],
    188: [function(e, t, r) {
        "use strict";
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.crypto = void 0,
            r.crypto = "object" == typeof globalThis && "crypto"in globalThis ? globalThis.crypto : void 0
    }
        , {}],
    189: [function(e, t, r) {
        "use strict";
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.shake256 = r.shake128 = r.keccak_512 = r.keccak_384 = r.keccak_256 = r.keccak_224 = r.sha3_512 = r.sha3_384 = r.sha3_256 = r.sha3_224 = r.Keccak = void 0,
            r.keccakP = w;
        const n = e("./_assert.js")
            , s = e("./_u64.js")
            , o = e("./utils.js")
            , i = []
            , a = []
            , c = []
            , u = BigInt(0)
            , l = BigInt(1)
            , d = BigInt(2)
            , f = BigInt(7)
            , p = BigInt(256)
            , h = BigInt(113);
        for (let e = 0, t = l, r = 1, n = 0; e < 24; e++) {
            [r,n] = [n, (2 * r + 3 * n) % 5],
                i.push(2 * (5 * n + r)),
                a.push((e + 1) * (e + 2) / 2 % 64);
            let s = u;
            for (let e = 0; e < 7; e++)
                t = (t << l ^ (t >> f) * h) % p,
                t & d && (s ^= l << (l << BigInt(e)) - l);
            c.push(s)
        }
        const [g,m] = (0,
            s.split)(c, !0)
            , b = (e, t, r) => r > 32 ? (0,
            s.rotlBH)(e, t, r) : (0,
            s.rotlSH)(e, t, r)
            , y = (e, t, r) => r > 32 ? (0,
            s.rotlBL)(e, t, r) : (0,
            s.rotlSL)(e, t, r);
        function w(e, t=24) {
            const r = new Uint32Array(10);
            for (let n = 24 - t; n < 24; n++) {
                for (let t = 0; t < 10; t++)
                    r[t] = e[t] ^ e[t + 10] ^ e[t + 20] ^ e[t + 30] ^ e[t + 40];
                for (let t = 0; t < 10; t += 2) {
                    const n = (t + 8) % 10
                        , s = (t + 2) % 10
                        , o = r[s]
                        , i = r[s + 1]
                        , a = b(o, i, 1) ^ r[n]
                        , c = y(o, i, 1) ^ r[n + 1];
                    for (let r = 0; r < 50; r += 10)
                        e[t + r] ^= a,
                            e[t + r + 1] ^= c
                }
                let t = e[2]
                    , s = e[3];
                for (let r = 0; r < 24; r++) {
                    const n = a[r]
                        , o = b(t, s, n)
                        , c = y(t, s, n)
                        , u = i[r];
                    t = e[u],
                        s = e[u + 1],
                        e[u] = o,
                        e[u + 1] = c
                }
                for (let t = 0; t < 50; t += 10) {
                    for (let n = 0; n < 10; n++)
                        r[n] = e[t + n];
                    for (let n = 0; n < 10; n++)
                        e[t + n] ^= ~r[(n + 2) % 10] & r[(n + 4) % 10]
                }
                e[0] ^= g[n],
                    e[1] ^= m[n]
            }
            r.fill(0)
        }
        class v extends o.Hash {
            constructor(e, t, r, s=!1, i=24) {
                if (super(),
                    this.blockLen = e,
                    this.suffix = t,
                    this.outputLen = r,
                    this.enableXOF = s,
                    this.rounds = i,
                    this.pos = 0,
                    this.posOut = 0,
                    this.finished = !1,
                    this.destroyed = !1,
                    (0,
                        n.number)(r),
                0 >= this.blockLen || this.blockLen >= 200)
                    throw new Error("Sha3 supports only keccak-f1600 function");
                this.state = new Uint8Array(200),
                    this.state32 = (0,
                        o.u32)(this.state)
            }
            keccak() {
                o.isLE || (0,
                    o.byteSwap32)(this.state32),
                    w(this.state32, this.rounds),
                o.isLE || (0,
                    o.byteSwap32)(this.state32),
                    this.posOut = 0,
                    this.pos = 0
            }
            update(e) {
                (0,
                    n.exists)(this);
                const {blockLen: t, state: r} = this
                    , s = (e = (0,
                    o.toBytes)(e)).length;
                for (let n = 0; n < s; ) {
                    const o = Math.min(t - this.pos, s - n);
                    for (let t = 0; t < o; t++)
                        r[this.pos++] ^= e[n++];
                    this.pos === t && this.keccak()
                }
                return this
            }
            finish() {
                if (this.finished)
                    return;
                this.finished = !0;
                const {state: e, suffix: t, pos: r, blockLen: n} = this;
                e[r] ^= t,
                128 & t && r === n - 1 && this.keccak(),
                    e[n - 1] ^= 128,
                    this.keccak()
            }
            writeInto(e) {
                (0,
                    n.exists)(this, !1),
                    (0,
                        n.bytes)(e),
                    this.finish();
                const t = this.state
                    , {blockLen: r} = this;
                for (let n = 0, s = e.length; n < s; ) {
                    this.posOut >= r && this.keccak();
                    const o = Math.min(r - this.posOut, s - n);
                    e.set(t.subarray(this.posOut, this.posOut + o), n),
                        this.posOut += o,
                        n += o
                }
                return e
            }
            xofInto(e) {
                if (!this.enableXOF)
                    throw new Error("XOF is not possible for this instance");
                return this.writeInto(e)
            }
            xof(e) {
                return (0,
                    n.number)(e),
                    this.xofInto(new Uint8Array(e))
            }
            digestInto(e) {
                if ((0,
                    n.output)(e, this),
                    this.finished)
                    throw new Error("digest() was already called");
                return this.writeInto(e),
                    this.destroy(),
                    e
            }
            digest() {
                return this.digestInto(new Uint8Array(this.outputLen))
            }
            destroy() {
                this.destroyed = !0,
                    this.state.fill(0)
            }
            _cloneInto(e) {
                const {blockLen: t, suffix: r, outputLen: n, rounds: s, enableXOF: o} = this;
                return e || (e = new v(t,r,n,o,s)),
                    e.state32.set(this.state32),
                    e.pos = this.pos,
                    e.posOut = this.posOut,
                    e.finished = this.finished,
                    e.rounds = s,
                    e.suffix = r,
                    e.outputLen = n,
                    e.enableXOF = o,
                    e.destroyed = this.destroyed,
                    e
            }
        }
        r.Keccak = v;
        const _ = (e, t, r) => (0,
            o.wrapConstructor)(( () => new v(t,e,r)));
        r.sha3_224 = _(6, 144, 28),
            r.sha3_256 = _(6, 136, 32),
            r.sha3_384 = _(6, 104, 48),
            r.sha3_512 = _(6, 72, 64),
            r.keccak_224 = _(1, 144, 28),
            r.keccak_256 = _(1, 136, 32),
            r.keccak_384 = _(1, 104, 48),
            r.keccak_512 = _(1, 72, 64);
        const E = (e, t, r) => (0,
            o.wrapXOFConstructorWithOpts)(( (n={}) => new v(t,e,void 0 === n.dkLen ? r : n.dkLen,!0)));
        r.shake128 = E(31, 168, 16),
            r.shake256 = E(31, 136, 32)
    }
        , {
            "./_assert.js": 186,
            "./_u64.js": 187,
            "./utils.js": 190
        }],
    190: [function(e, t, r) {
        "use strict";
        /*! noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com) */
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.Hash = r.nextTick = r.byteSwapIfBE = r.byteSwap = r.isLE = r.rotl = r.rotr = r.createView = r.u32 = r.u8 = void 0,
            r.isBytes = function(e) {
                return e instanceof Uint8Array || null != e && "object" == typeof e && "Uint8Array" === e.constructor.name
            }
            ,
            r.byteSwap32 = function(e) {
                for (let t = 0; t < e.length; t++)
                    e[t] = (0,
                        r.byteSwap)(e[t])
            }
            ,
            r.bytesToHex = function(e) {
                (0,
                    s.bytes)(e);
                let t = "";
                for (let r = 0; r < e.length; r++)
                    t += o[e[r]];
                return t
            }
            ,
            r.hexToBytes = function(e) {
                if ("string" != typeof e)
                    throw new Error("hex string expected, got " + typeof e);
                const t = e.length
                    , r = t / 2;
                if (t % 2)
                    throw new Error("padded hex string expected, got unpadded hex of length " + t);
                const n = new Uint8Array(r);
                for (let t = 0, s = 0; t < r; t++,
                    s += 2) {
                    const r = a(e.charCodeAt(s))
                        , o = a(e.charCodeAt(s + 1));
                    if (void 0 === r || void 0 === o) {
                        const t = e[s] + e[s + 1];
                        throw new Error('hex string expected, got non-hex character "' + t + '" at index ' + s)
                    }
                    n[t] = 16 * r + o
                }
                return n
            }
            ,
            r.asyncLoop = async function(e, t, n) {
                let s = Date.now();
                for (let o = 0; o < e; o++) {
                    n(o);
                    const e = Date.now() - s;
                    e >= 0 && e < t || (await (0,
                        r.nextTick)(),
                        s += e)
                }
            }
            ,
            r.utf8ToBytes = c,
            r.toBytes = u,
            r.concatBytes = function(...e) {
                let t = 0;
                for (let r = 0; r < e.length; r++) {
                    const n = e[r];
                    (0,
                        s.bytes)(n),
                        t += n.length
                }
                const r = new Uint8Array(t);
                for (let t = 0, n = 0; t < e.length; t++) {
                    const s = e[t];
                    r.set(s, n),
                        n += s.length
                }
                return r
            }
            ,
            r.checkOpts = function(e, t) {
                if (void 0 !== t && "[object Object]" !== l.call(t))
                    throw new Error("Options should be object or undefined");
                return Object.assign(e, t)
            }
            ,
            r.wrapConstructor = function(e) {
                const t = t => e().update(u(t)).digest()
                    , r = e();
                return t.outputLen = r.outputLen,
                    t.blockLen = r.blockLen,
                    t.create = () => e(),
                    t
            }
            ,
            r.wrapConstructorWithOpts = function(e) {
                const t = (t, r) => e(r).update(u(t)).digest()
                    , r = e({});
                return t.outputLen = r.outputLen,
                    t.blockLen = r.blockLen,
                    t.create = t => e(t),
                    t
            }
            ,
            r.wrapXOFConstructorWithOpts = function(e) {
                const t = (t, r) => e(r).update(u(t)).digest()
                    , r = e({});
                return t.outputLen = r.outputLen,
                    t.blockLen = r.blockLen,
                    t.create = t => e(t),
                    t
            }
            ,
            r.randomBytes = function(e=32) {
                if (n.crypto && "function" == typeof n.crypto.getRandomValues)
                    return n.crypto.getRandomValues(new Uint8Array(e));
                if (n.crypto && "function" == typeof n.crypto.randomBytes)
                    return n.crypto.randomBytes(e);
                throw new Error("crypto.getRandomValues must be defined")
            }
        ;
        const n = e("@noble/hashes/crypto")
            , s = e("./_assert.js");
        r.u8 = e => new Uint8Array(e.buffer,e.byteOffset,e.byteLength);
        r.u32 = e => new Uint32Array(e.buffer,e.byteOffset,Math.floor(e.byteLength / 4));
        r.createView = e => new DataView(e.buffer,e.byteOffset,e.byteLength);
        r.rotr = (e, t) => e << 32 - t | e >>> t;
        r.rotl = (e, t) => e << t | e >>> 32 - t >>> 0,
            r.isLE = 68 === new Uint8Array(new Uint32Array([287454020]).buffer)[0];
        r.byteSwap = e => e << 24 & 4278190080 | e << 8 & 16711680 | e >>> 8 & 65280 | e >>> 24 & 255,
            r.byteSwapIfBE = r.isLE ? e => e : e => (0,
                r.byteSwap)(e);
        const o = Array.from({
            length: 256
        }, ( (e, t) => t.toString(16).padStart(2, "0")));
        const i = {
            _0: 48,
            _9: 57,
            _A: 65,
            _F: 70,
            _a: 97,
            _f: 102
        };
        function a(e) {
            return e >= i._0 && e <= i._9 ? e - i._0 : e >= i._A && e <= i._F ? e - (i._A - 10) : e >= i._a && e <= i._f ? e - (i._a - 10) : void 0
        }
        function c(e) {
            if ("string" != typeof e)
                throw new Error("utf8ToBytes expected string, got " + typeof e);
            return new Uint8Array((new TextEncoder).encode(e))
        }
        function u(e) {
            return "string" == typeof e && (e = c(e)),
                (0,
                    s.bytes)(e),
                e
        }
        r.nextTick = async () => {}
        ;
        r.Hash = class {
            clone() {
                return this._cloneInto()
            }
        }
        ;
        const l = {}.toString
    }
        , {
            "./_assert.js": 186,
            "@noble/hashes/crypto": 188
        }],
    191: [function(e, t, r) {
        "use strict";
        /*! scure-base - MIT License (c) 2022 Paul Miller (paulmillr.com) */
        function n(e) {
            if (!Number.isSafeInteger(e))
                throw new Error(`Wrong integer: ${e}`)
        }
        function s(e) {
            return e instanceof Uint8Array || null != e && "object" == typeof e && "Uint8Array" === e.constructor.name
        }
        function o(...e) {
            const t = e => e
                , r = (e, t) => r => e(t(r));
            return {
                encode: e.map((e => e.encode)).reduceRight(r, t),
                decode: e.map((e => e.decode)).reduce(r, t)
            }
        }
        function i(e) {
            return {
                encode: t => {
                    if (!Array.isArray(t) || t.length && "number" != typeof t[0])
                        throw new Error("alphabet.encode input should be an array of numbers");
                    return t.map((t => {
                            if (n(t),
                            t < 0 || t >= e.length)
                                throw new Error(`Digit index outside alphabet: ${t} (alphabet: ${e.length})`);
                            return e[t]
                        }
                    ))
                }
                ,
                decode: t => {
                    if (!Array.isArray(t) || t.length && "string" != typeof t[0])
                        throw new Error("alphabet.decode input should be array of strings");
                    return t.map((t => {
                            if ("string" != typeof t)
                                throw new Error(`alphabet.decode: not string element=${t}`);
                            const r = e.indexOf(t);
                            if (-1 === r)
                                throw new Error(`Unknown letter: "${t}". Allowed: ${e}`);
                            return r
                        }
                    ))
                }
            }
        }
        function a(e="") {
            if ("string" != typeof e)
                throw new Error("join separator should be string");
            return {
                encode: t => {
                    if (!Array.isArray(t) || t.length && "string" != typeof t[0])
                        throw new Error("join.encode input should be array of strings");
                    for (let e of t)
                        if ("string" != typeof e)
                            throw new Error(`join.encode: non-string input=${e}`);
                    return t.join(e)
                }
                ,
                decode: t => {
                    if ("string" != typeof t)
                        throw new Error("join.decode input should be string");
                    return t.split(e)
                }
            }
        }
        function c(e, t="=") {
            if (n(e),
            "string" != typeof t)
                throw new Error("padding chr should be string");
            return {
                encode(r) {
                    if (!Array.isArray(r) || r.length && "string" != typeof r[0])
                        throw new Error("padding.encode input should be array of strings");
                    for (let e of r)
                        if ("string" != typeof e)
                            throw new Error(`padding.encode: non-string input=${e}`);
                    for (; r.length * e % 8; )
                        r.push(t);
                    return r
                },
                decode(r) {
                    if (!Array.isArray(r) || r.length && "string" != typeof r[0])
                        throw new Error("padding.encode input should be array of strings");
                    for (let e of r)
                        if ("string" != typeof e)
                            throw new Error(`padding.decode: non-string input=${e}`);
                    let n = r.length;
                    if (n * e % 8)
                        throw new Error("Invalid padding: string should have whole number of bytes");
                    for (; n > 0 && r[n - 1] === t; n--)
                        if (!((n - 1) * e % 8))
                            throw new Error("Invalid padding: string has too much padding");
                    return r.slice(0, n)
                }
            }
        }
        function u(e) {
            if ("function" != typeof e)
                throw new Error("normalize fn should be function");
            return {
                encode: e => e,
                decode: t => e(t)
            }
        }
        function l(e, t, r) {
            if (t < 2)
                throw new Error(`convertRadix: wrong from=${t}, base cannot be less than 2`);
            if (r < 2)
                throw new Error(`convertRadix: wrong to=${r}, base cannot be less than 2`);
            if (!Array.isArray(e))
                throw new Error("convertRadix: data should be array");
            if (!e.length)
                return [];
            let s = 0;
            const o = []
                , i = Array.from(e);
            for (i.forEach((e => {
                    if (n(e),
                    e < 0 || e >= t)
                        throw new Error(`Wrong integer: ${e}`)
                }
            )); ; ) {
                let e = 0
                    , n = !0;
                for (let o = s; o < i.length; o++) {
                    const a = i[o]
                        , c = t * e + a;
                    if (!Number.isSafeInteger(c) || t * e / t !== e || c - a != t * e)
                        throw new Error("convertRadix: carry overflow");
                    e = c % r;
                    const u = Math.floor(c / r);
                    if (i[o] = u,
                    !Number.isSafeInteger(u) || u * r + e !== c)
                        throw new Error("convertRadix: carry overflow");
                    n && (u ? n = !1 : s = o)
                }
                if (o.push(e),
                    n)
                    break
            }
            for (let t = 0; t < e.length - 1 && 0 === e[t]; t++)
                o.push(0);
            return o.reverse()
        }
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.bytes = r.stringToBytes = r.str = r.bytesToString = r.hex = r.utf8 = r.bech32m = r.bech32 = r.base58check = r.createBase58check = r.base58xmr = r.base58xrp = r.base58flickr = r.base58 = r.base64urlnopad = r.base64url = r.base64nopad = r.base64 = r.base32crockford = r.base32hexnopad = r.base32hex = r.base32nopad = r.base32 = r.base16 = r.utils = r.assertNumber = void 0,
            r.assertNumber = n;
        const d = (e, t) => t ? d(t, e % t) : e
            , f = (e, t) => e + (t - d(e, t));
        function p(e, t, r, s) {
            if (!Array.isArray(e))
                throw new Error("convertRadix2: data should be array");
            if (t <= 0 || t > 32)
                throw new Error(`convertRadix2: wrong from=${t}`);
            if (r <= 0 || r > 32)
                throw new Error(`convertRadix2: wrong to=${r}`);
            if (f(t, r) > 32)
                throw new Error(`convertRadix2: carry overflow from=${t} to=${r} carryBits=${f(t, r)}`);
            let o = 0
                , i = 0;
            const a = 2 ** r - 1
                , c = [];
            for (const s of e) {
                if (n(s),
                s >= 2 ** t)
                    throw new Error(`convertRadix2: invalid data word=${s} from=${t}`);
                if (o = o << t | s,
                i + t > 32)
                    throw new Error(`convertRadix2: carry overflow pos=${i} from=${t}`);
                for (i += t; i >= r; i -= r)
                    c.push((o >> i - r & a) >>> 0);
                o &= 2 ** i - 1
            }
            if (o = o << r - i & a,
            !s && i >= t)
                throw new Error("Excess padding");
            if (!s && o)
                throw new Error(`Non-zero padding: ${o}`);
            return s && i > 0 && c.push(o >>> 0),
                c
        }
        function h(e) {
            return n(e),
                {
                    encode: t => {
                        if (!s(t))
                            throw new Error("radix.encode input should be Uint8Array");
                        return l(Array.from(t), 256, e)
                    }
                    ,
                    decode: t => {
                        if (!Array.isArray(t) || t.length && "number" != typeof t[0])
                            throw new Error("radix.decode input should be array of numbers");
                        return Uint8Array.from(l(t, e, 256))
                    }
                }
        }
        function g(e, t=!1) {
            if (n(e),
            e <= 0 || e > 32)
                throw new Error("radix2: bits should be in (0..32]");
            if (f(8, e) > 32 || f(e, 8) > 32)
                throw new Error("radix2: carry overflow");
            return {
                encode: r => {
                    if (!s(r))
                        throw new Error("radix2.encode input should be Uint8Array");
                    return p(Array.from(r), 8, e, !t)
                }
                ,
                decode: r => {
                    if (!Array.isArray(r) || r.length && "number" != typeof r[0])
                        throw new Error("radix2.decode input should be array of numbers");
                    return Uint8Array.from(p(r, e, 8, t))
                }
            }
        }
        function m(e) {
            if ("function" != typeof e)
                throw new Error("unsafeWrapper fn should be function");
            return function(...t) {
                try {
                    return e.apply(null, t)
                } catch (e) {}
            }
        }
        function b(e, t) {
            if (n(e),
            "function" != typeof t)
                throw new Error("checksum fn should be function");
            return {
                encode(r) {
                    if (!s(r))
                        throw new Error("checksum.encode: input should be Uint8Array");
                    const n = t(r).slice(0, e)
                        , o = new Uint8Array(r.length + e);
                    return o.set(r),
                        o.set(n, r.length),
                        o
                },
                decode(r) {
                    if (!s(r))
                        throw new Error("checksum.decode: input should be Uint8Array");
                    const n = r.slice(0, -e)
                        , o = t(n).slice(0, e)
                        , i = r.slice(-e);
                    for (let t = 0; t < e; t++)
                        if (o[t] !== i[t])
                            throw new Error("Invalid checksum");
                    return n
                }
            }
        }
        r.utils = {
            alphabet: i,
            chain: o,
            checksum: b,
            convertRadix: l,
            convertRadix2: p,
            radix: h,
            radix2: g,
            join: a,
            padding: c
        },
            r.base16 = o(g(4), i("0123456789ABCDEF"), a("")),
            r.base32 = o(g(5), i("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"), c(5), a("")),
            r.base32nopad = o(g(5), i("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"), a("")),
            r.base32hex = o(g(5), i("0123456789ABCDEFGHIJKLMNOPQRSTUV"), c(5), a("")),
            r.base32hexnopad = o(g(5), i("0123456789ABCDEFGHIJKLMNOPQRSTUV"), a("")),
            r.base32crockford = o(g(5), i("0123456789ABCDEFGHJKMNPQRSTVWXYZ"), a(""), u((e => e.toUpperCase().replace(/O/g, "0").replace(/[IL]/g, "1")))),
            r.base64 = o(g(6), i("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"), c(6), a("")),
            r.base64nopad = o(g(6), i("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"), a("")),
            r.base64url = o(g(6), i("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"), c(6), a("")),
            r.base64urlnopad = o(g(6), i("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"), a(""));
        const y = e => o(h(58), i(e), a(""));
        r.base58 = y("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"),
            r.base58flickr = y("123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ"),
            r.base58xrp = y("rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz");
        const w = [0, 2, 3, 5, 6, 7, 9, 10, 11];
        r.base58xmr = {
            encode(e) {
                let t = "";
                for (let n = 0; n < e.length; n += 8) {
                    const s = e.subarray(n, n + 8);
                    t += r.base58.encode(s).padStart(w[s.length], "1")
                }
                return t
            },
            decode(e) {
                let t = [];
                for (let n = 0; n < e.length; n += 11) {
                    const s = e.slice(n, n + 11)
                        , o = w.indexOf(s.length)
                        , i = r.base58.decode(s);
                    for (let e = 0; e < i.length - o; e++)
                        if (0 !== i[e])
                            throw new Error("base58xmr: wrong padding");
                    t = t.concat(Array.from(i.slice(i.length - o)))
                }
                return Uint8Array.from(t)
            }
        };
        r.createBase58check = e => o(b(4, (t => e(e(t)))), r.base58),
            r.base58check = r.createBase58check;
        const v = o(i("qpzry9x8gf2tvdw0s3jn54khce6mua7l"), a(""))
            , _ = [996825010, 642813549, 513874426, 1027748829, 705979059];
        function E(e) {
            const t = e >> 25;
            let r = (33554431 & e) << 5;
            for (let e = 0; e < _.length; e++)
                1 == (t >> e & 1) && (r ^= _[e]);
            return r
        }
        function S(e, t, r=1) {
            const n = e.length;
            let s = 1;
            for (let t = 0; t < n; t++) {
                const r = e.charCodeAt(t);
                if (r < 33 || r > 126)
                    throw new Error(`Invalid prefix (${e})`);
                s = E(s) ^ r >> 5
            }
            s = E(s);
            for (let t = 0; t < n; t++)
                s = E(s) ^ 31 & e.charCodeAt(t);
            for (let e of t)
                s = E(s) ^ e;
            for (let e = 0; e < 6; e++)
                s = E(s);
            return s ^= r,
                v.encode(p([s % 2 ** 30], 30, 5, !1))
        }
        function j(e) {
            const t = "bech32" === e ? 1 : 734539939
                , r = g(5)
                , n = r.decode
                , s = r.encode
                , o = m(n);
            function i(e, r=90) {
                if ("string" != typeof e)
                    throw new Error("bech32.decode input should be string, not " + typeof e);
                if (e.length < 8 || !1 !== r && e.length > r)
                    throw new TypeError(`Wrong string length: ${e.length} (${e}). Expected (8..${r})`);
                const n = e.toLowerCase();
                if (e !== n && e !== e.toUpperCase())
                    throw new Error("String must be lowercase or uppercase");
                const s = n.lastIndexOf("1");
                if (0 === s || -1 === s)
                    throw new Error('Letter "1" must be present between prefix and data only');
                const o = n.slice(0, s)
                    , i = n.slice(s + 1);
                if (i.length < 6)
                    throw new Error("Data must be at least 6 characters long");
                const a = v.decode(i).slice(0, -6)
                    , c = S(o, a, t);
                if (!i.endsWith(c))
                    throw new Error(`Invalid checksum in ${e}: expected "${c}"`);
                return {
                    prefix: o,
                    words: a
                }
            }
            return {
                encode: function(e, r, n=90) {
                    if ("string" != typeof e)
                        throw new Error("bech32.encode prefix should be string, not " + typeof e);
                    if (!Array.isArray(r) || r.length && "number" != typeof r[0])
                        throw new Error("bech32.encode words should be array of numbers, not " + typeof r);
                    if (0 === e.length)
                        throw new TypeError(`Invalid prefix length ${e.length}`);
                    const s = e.length + 7 + r.length;
                    if (!1 !== n && s > n)
                        throw new TypeError(`Length ${s} exceeds limit ${n}`);
                    const o = e.toLowerCase()
                        , i = S(o, r, t);
                    return `${o}1${v.encode(r)}${i}`
                },
                decode: i,
                decodeToBytes: function(e) {
                    const {prefix: t, words: r} = i(e, !1);
                    return {
                        prefix: t,
                        words: r,
                        bytes: n(r)
                    }
                },
                decodeUnsafe: m(i),
                fromWords: n,
                fromWordsUnsafe: o,
                toWords: s
            }
        }
        r.bech32 = j("bech32"),
            r.bech32m = j("bech32m"),
            r.utf8 = {
                encode: e => (new TextDecoder).decode(e),
                decode: e => (new TextEncoder).encode(e)
            },
            r.hex = o(g(4), i("0123456789abcdef"), a(""), u((e => {
                    if ("string" != typeof e || e.length % 2)
                        throw new TypeError(`hex.decode: expected string, got ${typeof e} with length ${e.length}`);
                    return e.toLowerCase()
                }
            )));
        const R = {
            utf8: r.utf8,
            hex: r.hex,
            base16: r.base16,
            base32: r.base32,
            base64: r.base64,
            base64url: r.base64url,
            base58: r.base58,
            base58xmr: r.base58xmr
        }
            , I = "Invalid encoding type. Available types: utf8, hex, base16, base32, base64, base64url, base58, base58xmr";
        r.bytesToString = (e, t) => {
            if ("string" != typeof e || !R.hasOwnProperty(e))
                throw new TypeError(I);
            if (!s(t))
                throw new TypeError("bytesToString() expects Uint8Array");
            return R[e].encode(t)
        }
            ,
            r.str = r.bytesToString;
        r.stringToBytes = (e, t) => {
            if (!R.hasOwnProperty(e))
                throw new TypeError(I);
            if ("string" != typeof t)
                throw new TypeError("stringToBytes() expects string");
            return R[e].decode(t)
        }
            ,
            r.bytes = r.stringToBytes
    }
        , {}],
    192: [function(e, t, r) {
        "use strict";
        const {AbortController: n} = globalThis;
        t.exports = {
            AbortController: n
        }
    }
        , {}],
    193: [function(e, t, r) {
        "use strict";
        r.byteLength = function(e) {
            var t = c(e)
                , r = t[0]
                , n = t[1];
            return 3 * (r + n) / 4 - n
        }
            ,
            r.toByteArray = function(e) {
                var t, r, n = c(e), i = n[0], a = n[1], u = new o(function(e, t, r) {
                    return 3 * (t + r) / 4 - r
                }(0, i, a)), l = 0, d = a > 0 ? i - 4 : i;
                for (r = 0; r < d; r += 4)
                    t = s[e.charCodeAt(r)] << 18 | s[e.charCodeAt(r + 1)] << 12 | s[e.charCodeAt(r + 2)] << 6 | s[e.charCodeAt(r + 3)],
                        u[l++] = t >> 16 & 255,
                        u[l++] = t >> 8 & 255,
                        u[l++] = 255 & t;
                2 === a && (t = s[e.charCodeAt(r)] << 2 | s[e.charCodeAt(r + 1)] >> 4,
                    u[l++] = 255 & t);
                1 === a && (t = s[e.charCodeAt(r)] << 10 | s[e.charCodeAt(r + 1)] << 4 | s[e.charCodeAt(r + 2)] >> 2,
                    u[l++] = t >> 8 & 255,
                    u[l++] = 255 & t);
                return u
            }
            ,
            r.fromByteArray = function(e) {
                for (var t, r = e.length, s = r % 3, o = [], i = 16383, a = 0, c = r - s; a < c; a += i)
                    o.push(u(e, a, a + i > c ? c : a + i));
                1 === s ? (t = e[r - 1],
                    o.push(n[t >> 2] + n[t << 4 & 63] + "==")) : 2 === s && (t = (e[r - 2] << 8) + e[r - 1],
                    o.push(n[t >> 10] + n[t >> 4 & 63] + n[t << 2 & 63] + "="));
                return o.join("")
            }
        ;
        for (var n = [], s = [], o = "undefined" != typeof Uint8Array ? Uint8Array : Array, i = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", a = 0; a < 64; ++a)
            n[a] = i[a],
                s[i.charCodeAt(a)] = a;
        function c(e) {
            var t = e.length;
            if (t % 4 > 0)
                throw new Error("Invalid string. Length must be a multiple of 4");
            var r = e.indexOf("=");
            return -1 === r && (r = t),
                [r, r === t ? 0 : 4 - r % 4]
        }
        function u(e, t, r) {
            for (var s, o, i = [], a = t; a < r; a += 3)
                s = (e[a] << 16 & 16711680) + (e[a + 1] << 8 & 65280) + (255 & e[a + 2]),
                    i.push(n[(o = s) >> 18 & 63] + n[o >> 12 & 63] + n[o >> 6 & 63] + n[63 & o]);
            return i.join("")
        }
        s["-".charCodeAt(0)] = 62,
            s["_".charCodeAt(0)] = 63
    }
        , {}],
    194: [function(e, t, r) {}
        , {}],
    195: [function(e, t, r) {
        /*!
 * The buffer module from node.js, for the browser.
 *
 * @author   Feross Aboukhadijeh <https://feross.org>
 * @license  MIT
 */
        "use strict";
        var n = e("base64-js")
            , s = e("ieee754");
        r.Buffer = a,
            r.SlowBuffer = function(e) {
                +e != e && (e = 0);
                return a.alloc(+e)
            }
            ,
            r.INSPECT_MAX_BYTES = 50;
        var o = 2147483647;
        function i(e) {
            if (e > o)
                throw new RangeError('The value "' + e + '" is invalid for option "size"');
            var t = new Uint8Array(e);
            return t.__proto__ = a.prototype,
                t
        }
        function a(e, t, r) {
            if ("number" == typeof e) {
                if ("string" == typeof t)
                    throw new TypeError('The "string" argument must be of type string. Received type number');
                return l(e)
            }
            return c(e, t, r)
        }
        function c(e, t, r) {
            if ("string" == typeof e)
                return function(e, t) {
                    "string" == typeof t && "" !== t || (t = "utf8");
                    if (!a.isEncoding(t))
                        throw new TypeError("Unknown encoding: " + t);
                    var r = 0 | p(e, t)
                        , n = i(r)
                        , s = n.write(e, t);
                    s !== r && (n = n.slice(0, s));
                    return n
                }(e, t);
            if (ArrayBuffer.isView(e))
                return d(e);
            if (null == e)
                throw TypeError("The first argument must be one of type string, Buffer, ArrayBuffer, Array, or Array-like Object. Received type " + typeof e);
            if (F(e, ArrayBuffer) || e && F(e.buffer, ArrayBuffer))
                return function(e, t, r) {
                    if (t < 0 || e.byteLength < t)
                        throw new RangeError('"offset" is outside of buffer bounds');
                    if (e.byteLength < t + (r || 0))
                        throw new RangeError('"length" is outside of buffer bounds');
                    var n;
                    n = void 0 === t && void 0 === r ? new Uint8Array(e) : void 0 === r ? new Uint8Array(e,t) : new Uint8Array(e,t,r);
                    return n.__proto__ = a.prototype,
                        n
                }(e, t, r);
            if ("number" == typeof e)
                throw new TypeError('The "value" argument must not be of type number. Received type number');
            var n = e.valueOf && e.valueOf();
            if (null != n && n !== e)
                return a.from(n, t, r);
            var s = function(e) {
                if (a.isBuffer(e)) {
                    var t = 0 | f(e.length)
                        , r = i(t);
                    return 0 === r.length || e.copy(r, 0, 0, t),
                        r
                }
                if (void 0 !== e.length)
                    return "number" != typeof e.length || W(e.length) ? i(0) : d(e);
                if ("Buffer" === e.type && Array.isArray(e.data))
                    return d(e.data)
            }(e);
            if (s)
                return s;
            if ("undefined" != typeof Symbol && null != Symbol.toPrimitive && "function" == typeof e[Symbol.toPrimitive])
                return a.from(e[Symbol.toPrimitive]("string"), t, r);
            throw new TypeError("The first argument must be one of type string, Buffer, ArrayBuffer, Array, or Array-like Object. Received type " + typeof e)
        }
        function u(e) {
            if ("number" != typeof e)
                throw new TypeError('"size" argument must be of type number');
            if (e < 0)
                throw new RangeError('The value "' + e + '" is invalid for option "size"')
        }
        function l(e) {
            return u(e),
                i(e < 0 ? 0 : 0 | f(e))
        }
        function d(e) {
            for (var t = e.length < 0 ? 0 : 0 | f(e.length), r = i(t), n = 0; n < t; n += 1)
                r[n] = 255 & e[n];
            return r
        }
        function f(e) {
            if (e >= o)
                throw new RangeError("Attempt to allocate Buffer larger than maximum size: 0x" + o.toString(16) + " bytes");
            return 0 | e
        }
        function p(e, t) {
            if (a.isBuffer(e))
                return e.length;
            if (ArrayBuffer.isView(e) || F(e, ArrayBuffer))
                return e.byteLength;
            if ("string" != typeof e)
                throw new TypeError('The "string" argument must be one of type string, Buffer, or ArrayBuffer. Received type ' + typeof e);
            var r = e.length
                , n = arguments.length > 2 && !0 === arguments[2];
            if (!n && 0 === r)
                return 0;
            for (var s = !1; ; )
                switch (t) {
                    case "ascii":
                    case "latin1":
                    case "binary":
                        return r;
                    case "utf8":
                    case "utf-8":
                        return B(e).length;
                    case "ucs2":
                    case "ucs-2":
                    case "utf16le":
                    case "utf-16le":
                        return 2 * r;
                    case "hex":
                        return r >>> 1;
                    case "base64":
                        return $(e).length;
                    default:
                        if (s)
                            return n ? -1 : B(e).length;
                        t = ("" + t).toLowerCase(),
                            s = !0
                }
        }
        function h(e, t, r) {
            var n = !1;
            if ((void 0 === t || t < 0) && (t = 0),
            t > this.length)
                return "";
            if ((void 0 === r || r > this.length) && (r = this.length),
            r <= 0)
                return "";
            if ((r >>>= 0) <= (t >>>= 0))
                return "";
            for (e || (e = "utf8"); ; )
                switch (e) {
                    case "hex":
                        return T(this, t, r);
                    case "utf8":
                    case "utf-8":
                        return R(this, t, r);
                    case "ascii":
                        return A(this, t, r);
                    case "latin1":
                    case "binary":
                        return M(this, t, r);
                    case "base64":
                        return j(this, t, r);
                    case "ucs2":
                    case "ucs-2":
                    case "utf16le":
                    case "utf-16le":
                        return C(this, t, r);
                    default:
                        if (n)
                            throw new TypeError("Unknown encoding: " + e);
                        e = (e + "").toLowerCase(),
                            n = !0
                }
        }
        function g(e, t, r) {
            var n = e[t];
            e[t] = e[r],
                e[r] = n
        }
        function m(e, t, r, n, s) {
            if (0 === e.length)
                return -1;
            if ("string" == typeof r ? (n = r,
                r = 0) : r > 2147483647 ? r = 2147483647 : r < -2147483648 && (r = -2147483648),
            W(r = +r) && (r = s ? 0 : e.length - 1),
            r < 0 && (r = e.length + r),
            r >= e.length) {
                if (s)
                    return -1;
                r = e.length - 1
            } else if (r < 0) {
                if (!s)
                    return -1;
                r = 0
            }
            if ("string" == typeof t && (t = a.from(t, n)),
                a.isBuffer(t))
                return 0 === t.length ? -1 : b(e, t, r, n, s);
            if ("number" == typeof t)
                return t &= 255,
                    "function" == typeof Uint8Array.prototype.indexOf ? s ? Uint8Array.prototype.indexOf.call(e, t, r) : Uint8Array.prototype.lastIndexOf.call(e, t, r) : b(e, [t], r, n, s);
            throw new TypeError("val must be string, number or Buffer")
        }
        function b(e, t, r, n, s) {
            var o, i = 1, a = e.length, c = t.length;
            if (void 0 !== n && ("ucs2" === (n = String(n).toLowerCase()) || "ucs-2" === n || "utf16le" === n || "utf-16le" === n)) {
                if (e.length < 2 || t.length < 2)
                    return -1;
                i = 2,
                    a /= 2,
                    c /= 2,
                    r /= 2
            }
            function u(e, t) {
                return 1 === i ? e[t] : e.readUInt16BE(t * i)
            }
            if (s) {
                var l = -1;
                for (o = r; o < a; o++)
                    if (u(e, o) === u(t, -1 === l ? 0 : o - l)) {
                        if (-1 === l && (l = o),
                        o - l + 1 === c)
                            return l * i
                    } else
                        -1 !== l && (o -= o - l),
                            l = -1
            } else
                for (r + c > a && (r = a - c),
                         o = r; o >= 0; o--) {
                    for (var d = !0, f = 0; f < c; f++)
                        if (u(e, o + f) !== u(t, f)) {
                            d = !1;
                            break
                        }
                    if (d)
                        return o
                }
            return -1
        }
        function y(e, t, r, n) {
            r = Number(r) || 0;
            var s = e.length - r;
            n ? (n = Number(n)) > s && (n = s) : n = s;
            var o = t.length;
            n > o / 2 && (n = o / 2);
            for (var i = 0; i < n; ++i) {
                var a = parseInt(t.substr(2 * i, 2), 16);
                if (W(a))
                    return i;
                e[r + i] = a
            }
            return i
        }
        function w(e, t, r, n) {
            return U(B(t, e.length - r), e, r, n)
        }
        function v(e, t, r, n) {
            return U(function(e) {
                for (var t = [], r = 0; r < e.length; ++r)
                    t.push(255 & e.charCodeAt(r));
                return t
            }(t), e, r, n)
        }
        function _(e, t, r, n) {
            return v(e, t, r, n)
        }
        function E(e, t, r, n) {
            return U($(t), e, r, n)
        }
        function S(e, t, r, n) {
            return U(function(e, t) {
                for (var r, n, s, o = [], i = 0; i < e.length && !((t -= 2) < 0); ++i)
                    n = (r = e.charCodeAt(i)) >> 8,
                        s = r % 256,
                        o.push(s),
                        o.push(n);
                return o
            }(t, e.length - r), e, r, n)
        }
        function j(e, t, r) {
            return 0 === t && r === e.length ? n.fromByteArray(e) : n.fromByteArray(e.slice(t, r))
        }
        function R(e, t, r) {
            r = Math.min(e.length, r);
            for (var n = [], s = t; s < r; ) {
                var o, i, a, c, u = e[s], l = null, d = u > 239 ? 4 : u > 223 ? 3 : u > 191 ? 2 : 1;
                if (s + d <= r)
                    switch (d) {
                        case 1:
                            u < 128 && (l = u);
                            break;
                        case 2:
                            128 == (192 & (o = e[s + 1])) && (c = (31 & u) << 6 | 63 & o) > 127 && (l = c);
                            break;
                        case 3:
                            o = e[s + 1],
                                i = e[s + 2],
                            128 == (192 & o) && 128 == (192 & i) && (c = (15 & u) << 12 | (63 & o) << 6 | 63 & i) > 2047 && (c < 55296 || c > 57343) && (l = c);
                            break;
                        case 4:
                            o = e[s + 1],
                                i = e[s + 2],
                                a = e[s + 3],
                            128 == (192 & o) && 128 == (192 & i) && 128 == (192 & a) && (c = (15 & u) << 18 | (63 & o) << 12 | (63 & i) << 6 | 63 & a) > 65535 && c < 1114112 && (l = c)
                    }
                null === l ? (l = 65533,
                    d = 1) : l > 65535 && (l -= 65536,
                    n.push(l >>> 10 & 1023 | 55296),
                    l = 56320 | 1023 & l),
                    n.push(l),
                    s += d
            }
            return function(e) {
                var t = e.length;
                if (t <= I)
                    return String.fromCharCode.apply(String, e);
                var r = ""
                    , n = 0;
                for (; n < t; )
                    r += String.fromCharCode.apply(String, e.slice(n, n += I));
                return r
            }(n)
        }
        r.kMaxLength = o,
            a.TYPED_ARRAY_SUPPORT = function() {
                try {
                    var e = new Uint8Array(1);
                    return e.__proto__ = {
                        __proto__: Uint8Array.prototype,
                        foo: function() {
                            return 42
                        }
                    },
                    42 === e.foo()
                } catch (e) {
                    return !1
                }
            }(),
        a.TYPED_ARRAY_SUPPORT || "undefined" == typeof console || "function" != typeof console.error || console.error("This browser lacks typed array (Uint8Array) support which is required by `buffer` v5.x. Use `buffer` v4.x if you require old browser support."),
            Object.defineProperty(a.prototype, "parent", {
                enumerable: !0,
                get: function() {
                    if (a.isBuffer(this))
                        return this.buffer
                }
            }),
            Object.defineProperty(a.prototype, "offset", {
                enumerable: !0,
                get: function() {
                    if (a.isBuffer(this))
                        return this.byteOffset
                }
            }),
        "undefined" != typeof Symbol && null != Symbol.species && a[Symbol.species] === a && Object.defineProperty(a, Symbol.species, {
            value: null,
            configurable: !0,
            enumerable: !1,
            writable: !1
        }),
            a.poolSize = 8192,
            a.from = function(e, t, r) {
                return c(e, t, r)
            }
            ,
            a.prototype.__proto__ = Uint8Array.prototype,
            a.__proto__ = Uint8Array,
            a.alloc = function(e, t, r) {
                return function(e, t, r) {
                    return u(e),
                        e <= 0 ? i(e) : void 0 !== t ? "string" == typeof r ? i(e).fill(t, r) : i(e).fill(t) : i(e)
                }(e, t, r)
            }
            ,
            a.allocUnsafe = function(e) {
                return l(e)
            }
            ,
            a.allocUnsafeSlow = function(e) {
                return l(e)
            }
            ,
            a.isBuffer = function(e) {
                return null != e && !0 === e._isBuffer && e !== a.prototype
            }
            ,
            a.compare = function(e, t) {
                if (F(e, Uint8Array) && (e = a.from(e, e.offset, e.byteLength)),
                F(t, Uint8Array) && (t = a.from(t, t.offset, t.byteLength)),
                !a.isBuffer(e) || !a.isBuffer(t))
                    throw new TypeError('The "buf1", "buf2" arguments must be one of type Buffer or Uint8Array');
                if (e === t)
                    return 0;
                for (var r = e.length, n = t.length, s = 0, o = Math.min(r, n); s < o; ++s)
                    if (e[s] !== t[s]) {
                        r = e[s],
                            n = t[s];
                        break
                    }
                return r < n ? -1 : n < r ? 1 : 0
            }
            ,
            a.isEncoding = function(e) {
                switch (String(e).toLowerCase()) {
                    case "hex":
                    case "utf8":
                    case "utf-8":
                    case "ascii":
                    case "latin1":
                    case "binary":
                    case "base64":
                    case "ucs2":
                    case "ucs-2":
                    case "utf16le":
                    case "utf-16le":
                        return !0;
                    default:
                        return !1
                }
            }
            ,
            a.concat = function(e, t) {
                if (!Array.isArray(e))
                    throw new TypeError('"list" argument must be an Array of Buffers');
                if (0 === e.length)
                    return a.alloc(0);
                var r;
                if (void 0 === t)
                    for (t = 0,
                             r = 0; r < e.length; ++r)
                        t += e[r].length;
                var n = a.allocUnsafe(t)
                    , s = 0;
                for (r = 0; r < e.length; ++r) {
                    var o = e[r];
                    if (F(o, Uint8Array) && (o = a.from(o)),
                        !a.isBuffer(o))
                        throw new TypeError('"list" argument must be an Array of Buffers');
                    o.copy(n, s),
                        s += o.length
                }
                return n
            }
            ,
            a.byteLength = p,
            a.prototype._isBuffer = !0,
            a.prototype.swap16 = function() {
                var e = this.length;
                if (e % 2 != 0)
                    throw new RangeError("Buffer size must be a multiple of 16-bits");
                for (var t = 0; t < e; t += 2)
                    g(this, t, t + 1);
                return this
            }
            ,
            a.prototype.swap32 = function() {
                var e = this.length;
                if (e % 4 != 0)
                    throw new RangeError("Buffer size must be a multiple of 32-bits");
                for (var t = 0; t < e; t += 4)
                    g(this, t, t + 3),
                        g(this, t + 1, t + 2);
                return this
            }
            ,
            a.prototype.swap64 = function() {
                var e = this.length;
                if (e % 8 != 0)
                    throw new RangeError("Buffer size must be a multiple of 64-bits");
                for (var t = 0; t < e; t += 8)
                    g(this, t, t + 7),
                        g(this, t + 1, t + 6),
                        g(this, t + 2, t + 5),
                        g(this, t + 3, t + 4);
                return this
            }
            ,
            a.prototype.toString = function() {
                var e = this.length;
                return 0 === e ? "" : 0 === arguments.length ? R(this, 0, e) : h.apply(this, arguments)
            }
            ,
            a.prototype.toLocaleString = a.prototype.toString,
            a.prototype.equals = function(e) {
                if (!a.isBuffer(e))
                    throw new TypeError("Argument must be a Buffer");
                return this === e || 0 === a.compare(this, e)
            }
            ,
            a.prototype.inspect = function() {
                var e = ""
                    , t = r.INSPECT_MAX_BYTES;
                return e = this.toString("hex", 0, t).replace(/(.{2})/g, "$1 ").trim(),
                this.length > t && (e += " ... "),
                "<Buffer " + e + ">"
            }
            ,
            a.prototype.compare = function(e, t, r, n, s) {
                if (F(e, Uint8Array) && (e = a.from(e, e.offset, e.byteLength)),
                    !a.isBuffer(e))
                    throw new TypeError('The "target" argument must be one of type Buffer or Uint8Array. Received type ' + typeof e);
                if (void 0 === t && (t = 0),
                void 0 === r && (r = e ? e.length : 0),
                void 0 === n && (n = 0),
                void 0 === s && (s = this.length),
                t < 0 || r > e.length || n < 0 || s > this.length)
                    throw new RangeError("out of range index");
                if (n >= s && t >= r)
                    return 0;
                if (n >= s)
                    return -1;
                if (t >= r)
                    return 1;
                if (this === e)
                    return 0;
                for (var o = (s >>>= 0) - (n >>>= 0), i = (r >>>= 0) - (t >>>= 0), c = Math.min(o, i), u = this.slice(n, s), l = e.slice(t, r), d = 0; d < c; ++d)
                    if (u[d] !== l[d]) {
                        o = u[d],
                            i = l[d];
                        break
                    }
                return o < i ? -1 : i < o ? 1 : 0
            }
            ,
            a.prototype.includes = function(e, t, r) {
                return -1 !== this.indexOf(e, t, r)
            }
            ,
            a.prototype.indexOf = function(e, t, r) {
                return m(this, e, t, r, !0)
            }
            ,
            a.prototype.lastIndexOf = function(e, t, r) {
                return m(this, e, t, r, !1)
            }
            ,
            a.prototype.write = function(e, t, r, n) {
                if (void 0 === t)
                    n = "utf8",
                        r = this.length,
                        t = 0;
                else if (void 0 === r && "string" == typeof t)
                    n = t,
                        r = this.length,
                        t = 0;
                else {
                    if (!isFinite(t))
                        throw new Error("Buffer.write(string, encoding, offset[, length]) is no longer supported");
                    t >>>= 0,
                        isFinite(r) ? (r >>>= 0,
                        void 0 === n && (n = "utf8")) : (n = r,
                            r = void 0)
                }
                var s = this.length - t;
                if ((void 0 === r || r > s) && (r = s),
                e.length > 0 && (r < 0 || t < 0) || t > this.length)
                    throw new RangeError("Attempt to write outside buffer bounds");
                n || (n = "utf8");
                for (var o = !1; ; )
                    switch (n) {
                        case "hex":
                            return y(this, e, t, r);
                        case "utf8":
                        case "utf-8":
                            return w(this, e, t, r);
                        case "ascii":
                            return v(this, e, t, r);
                        case "latin1":
                        case "binary":
                            return _(this, e, t, r);
                        case "base64":
                            return E(this, e, t, r);
                        case "ucs2":
                        case "ucs-2":
                        case "utf16le":
                        case "utf-16le":
                            return S(this, e, t, r);
                        default:
                            if (o)
                                throw new TypeError("Unknown encoding: " + n);
                            n = ("" + n).toLowerCase(),
                                o = !0
                    }
            }
            ,
            a.prototype.toJSON = function() {
                return {
                    type: "Buffer",
                    data: Array.prototype.slice.call(this._arr || this, 0)
                }
            }
        ;
        var I = 4096;
        function A(e, t, r) {
            var n = "";
            r = Math.min(e.length, r);
            for (var s = t; s < r; ++s)
                n += String.fromCharCode(127 & e[s]);
            return n
        }
        function M(e, t, r) {
            var n = "";
            r = Math.min(e.length, r);
            for (var s = t; s < r; ++s)
                n += String.fromCharCode(e[s]);
            return n
        }
        function T(e, t, r) {
            var n = e.length;
            (!t || t < 0) && (t = 0),
            (!r || r < 0 || r > n) && (r = n);
            for (var s = "", o = t; o < r; ++o)
                s += D(e[o]);
            return s
        }
        function C(e, t, r) {
            for (var n = e.slice(t, r), s = "", o = 0; o < n.length; o += 2)
                s += String.fromCharCode(n[o] + 256 * n[o + 1]);
            return s
        }
        function O(e, t, r) {
            if (e % 1 != 0 || e < 0)
                throw new RangeError("offset is not uint");
            if (e + t > r)
                throw new RangeError("Trying to access beyond buffer length")
        }
        function x(e, t, r, n, s, o) {
            if (!a.isBuffer(e))
                throw new TypeError('"buffer" argument must be a Buffer instance');
            if (t > s || t < o)
                throw new RangeError('"value" argument is out of bounds');
            if (r + n > e.length)
                throw new RangeError("Index out of range")
        }
        function N(e, t, r, n, s, o) {
            if (r + n > e.length)
                throw new RangeError("Index out of range");
            if (r < 0)
                throw new RangeError("Index out of range")
        }
        function P(e, t, r, n, o) {
            return t = +t,
                r >>>= 0,
            o || N(e, 0, r, 4),
                s.write(e, t, r, n, 23, 4),
            r + 4
        }
        function k(e, t, r, n, o) {
            return t = +t,
                r >>>= 0,
            o || N(e, 0, r, 8),
                s.write(e, t, r, n, 52, 8),
            r + 8
        }
        a.prototype.slice = function(e, t) {
            var r = this.length;
            (e = ~~e) < 0 ? (e += r) < 0 && (e = 0) : e > r && (e = r),
                (t = void 0 === t ? r : ~~t) < 0 ? (t += r) < 0 && (t = 0) : t > r && (t = r),
            t < e && (t = e);
            var n = this.subarray(e, t);
            return n.__proto__ = a.prototype,
                n
        }
            ,
            a.prototype.readUIntLE = function(e, t, r) {
                e >>>= 0,
                    t >>>= 0,
                r || O(e, t, this.length);
                for (var n = this[e], s = 1, o = 0; ++o < t && (s *= 256); )
                    n += this[e + o] * s;
                return n
            }
            ,
            a.prototype.readUIntBE = function(e, t, r) {
                e >>>= 0,
                    t >>>= 0,
                r || O(e, t, this.length);
                for (var n = this[e + --t], s = 1; t > 0 && (s *= 256); )
                    n += this[e + --t] * s;
                return n
            }
            ,
            a.prototype.readUInt8 = function(e, t) {
                return e >>>= 0,
                t || O(e, 1, this.length),
                    this[e]
            }
            ,
            a.prototype.readUInt16LE = function(e, t) {
                return e >>>= 0,
                t || O(e, 2, this.length),
                this[e] | this[e + 1] << 8
            }
            ,
            a.prototype.readUInt16BE = function(e, t) {
                return e >>>= 0,
                t || O(e, 2, this.length),
                this[e] << 8 | this[e + 1]
            }
            ,
            a.prototype.readUInt32LE = function(e, t) {
                return e >>>= 0,
                t || O(e, 4, this.length),
                (this[e] | this[e + 1] << 8 | this[e + 2] << 16) + 16777216 * this[e + 3]
            }
            ,
            a.prototype.readUInt32BE = function(e, t) {
                return e >>>= 0,
                t || O(e, 4, this.length),
                16777216 * this[e] + (this[e + 1] << 16 | this[e + 2] << 8 | this[e + 3])
            }
            ,
            a.prototype.readIntLE = function(e, t, r) {
                e >>>= 0,
                    t >>>= 0,
                r || O(e, t, this.length);
                for (var n = this[e], s = 1, o = 0; ++o < t && (s *= 256); )
                    n += this[e + o] * s;
                return n >= (s *= 128) && (n -= Math.pow(2, 8 * t)),
                    n
            }
            ,
            a.prototype.readIntBE = function(e, t, r) {
                e >>>= 0,
                    t >>>= 0,
                r || O(e, t, this.length);
                for (var n = t, s = 1, o = this[e + --n]; n > 0 && (s *= 256); )
                    o += this[e + --n] * s;
                return o >= (s *= 128) && (o -= Math.pow(2, 8 * t)),
                    o
            }
            ,
            a.prototype.readInt8 = function(e, t) {
                return e >>>= 0,
                t || O(e, 1, this.length),
                    128 & this[e] ? -1 * (255 - this[e] + 1) : this[e]
            }
            ,
            a.prototype.readInt16LE = function(e, t) {
                e >>>= 0,
                t || O(e, 2, this.length);
                var r = this[e] | this[e + 1] << 8;
                return 32768 & r ? 4294901760 | r : r
            }
            ,
            a.prototype.readInt16BE = function(e, t) {
                e >>>= 0,
                t || O(e, 2, this.length);
                var r = this[e + 1] | this[e] << 8;
                return 32768 & r ? 4294901760 | r : r
            }
            ,
            a.prototype.readInt32LE = function(e, t) {
                return e >>>= 0,
                t || O(e, 4, this.length),
                this[e] | this[e + 1] << 8 | this[e + 2] << 16 | this[e + 3] << 24
            }
            ,
            a.prototype.readInt32BE = function(e, t) {
                return e >>>= 0,
                t || O(e, 4, this.length),
                this[e] << 24 | this[e + 1] << 16 | this[e + 2] << 8 | this[e + 3]
            }
            ,
            a.prototype.readFloatLE = function(e, t) {
                return e >>>= 0,
                t || O(e, 4, this.length),
                    s.read(this, e, !0, 23, 4)
            }
            ,
            a.prototype.readFloatBE = function(e, t) {
                return e >>>= 0,
                t || O(e, 4, this.length),
                    s.read(this, e, !1, 23, 4)
            }
            ,
            a.prototype.readDoubleLE = function(e, t) {
                return e >>>= 0,
                t || O(e, 8, this.length),
                    s.read(this, e, !0, 52, 8)
            }
            ,
            a.prototype.readDoubleBE = function(e, t) {
                return e >>>= 0,
                t || O(e, 8, this.length),
                    s.read(this, e, !1, 52, 8)
            }
            ,
            a.prototype.writeUIntLE = function(e, t, r, n) {
                (e = +e,
                    t >>>= 0,
                    r >>>= 0,
                    n) || x(this, e, t, r, Math.pow(2, 8 * r) - 1, 0);
                var s = 1
                    , o = 0;
                for (this[t] = 255 & e; ++o < r && (s *= 256); )
                    this[t + o] = e / s & 255;
                return t + r
            }
            ,
            a.prototype.writeUIntBE = function(e, t, r, n) {
                (e = +e,
                    t >>>= 0,
                    r >>>= 0,
                    n) || x(this, e, t, r, Math.pow(2, 8 * r) - 1, 0);
                var s = r - 1
                    , o = 1;
                for (this[t + s] = 255 & e; --s >= 0 && (o *= 256); )
                    this[t + s] = e / o & 255;
                return t + r
            }
            ,
            a.prototype.writeUInt8 = function(e, t, r) {
                return e = +e,
                    t >>>= 0,
                r || x(this, e, t, 1, 255, 0),
                    this[t] = 255 & e,
                t + 1
            }
            ,
            a.prototype.writeUInt16LE = function(e, t, r) {
                return e = +e,
                    t >>>= 0,
                r || x(this, e, t, 2, 65535, 0),
                    this[t] = 255 & e,
                    this[t + 1] = e >>> 8,
                t + 2
            }
            ,
            a.prototype.writeUInt16BE = function(e, t, r) {
                return e = +e,
                    t >>>= 0,
                r || x(this, e, t, 2, 65535, 0),
                    this[t] = e >>> 8,
                    this[t + 1] = 255 & e,
                t + 2
            }
            ,
            a.prototype.writeUInt32LE = function(e, t, r) {
                return e = +e,
                    t >>>= 0,
                r || x(this, e, t, 4, 4294967295, 0),
                    this[t + 3] = e >>> 24,
                    this[t + 2] = e >>> 16,
                    this[t + 1] = e >>> 8,
                    this[t] = 255 & e,
                t + 4
            }
            ,
            a.prototype.writeUInt32BE = function(e, t, r) {
                return e = +e,
                    t >>>= 0,
                r || x(this, e, t, 4, 4294967295, 0),
                    this[t] = e >>> 24,
                    this[t + 1] = e >>> 16,
                    this[t + 2] = e >>> 8,
                    this[t + 3] = 255 & e,
                t + 4
            }
            ,
            a.prototype.writeIntLE = function(e, t, r, n) {
                if (e = +e,
                    t >>>= 0,
                    !n) {
                    var s = Math.pow(2, 8 * r - 1);
                    x(this, e, t, r, s - 1, -s)
                }
                var o = 0
                    , i = 1
                    , a = 0;
                for (this[t] = 255 & e; ++o < r && (i *= 256); )
                    e < 0 && 0 === a && 0 !== this[t + o - 1] && (a = 1),
                        this[t + o] = (e / i | 0) - a & 255;
                return t + r
            }
            ,
            a.prototype.writeIntBE = function(e, t, r, n) {
                if (e = +e,
                    t >>>= 0,
                    !n) {
                    var s = Math.pow(2, 8 * r - 1);
                    x(this, e, t, r, s - 1, -s)
                }
                var o = r - 1
                    , i = 1
                    , a = 0;
                for (this[t + o] = 255 & e; --o >= 0 && (i *= 256); )
                    e < 0 && 0 === a && 0 !== this[t + o + 1] && (a = 1),
                        this[t + o] = (e / i | 0) - a & 255;
                return t + r
            }
            ,
            a.prototype.writeInt8 = function(e, t, r) {
                return e = +e,
                    t >>>= 0,
                r || x(this, e, t, 1, 127, -128),
                e < 0 && (e = 255 + e + 1),
                    this[t] = 255 & e,
                t + 1
            }
            ,
            a.prototype.writeInt16LE = function(e, t, r) {
                return e = +e,
                    t >>>= 0,
                r || x(this, e, t, 2, 32767, -32768),
                    this[t] = 255 & e,
                    this[t + 1] = e >>> 8,
                t + 2
            }
            ,
            a.prototype.writeInt16BE = function(e, t, r) {
                return e = +e,
                    t >>>= 0,
                r || x(this, e, t, 2, 32767, -32768),
                    this[t] = e >>> 8,
                    this[t + 1] = 255 & e,
                t + 2
            }
            ,
            a.prototype.writeInt32LE = function(e, t, r) {
                return e = +e,
                    t >>>= 0,
                r || x(this, e, t, 4, 2147483647, -2147483648),
                    this[t] = 255 & e,
                    this[t + 1] = e >>> 8,
                    this[t + 2] = e >>> 16,
                    this[t + 3] = e >>> 24,
                t + 4
            }
            ,
            a.prototype.writeInt32BE = function(e, t, r) {
                return e = +e,
                    t >>>= 0,
                r || x(this, e, t, 4, 2147483647, -2147483648),
                e < 0 && (e = 4294967295 + e + 1),
                    this[t] = e >>> 24,
                    this[t + 1] = e >>> 16,
                    this[t + 2] = e >>> 8,
                    this[t + 3] = 255 & e,
                t + 4
            }
            ,
            a.prototype.writeFloatLE = function(e, t, r) {
                return P(this, e, t, !0, r)
            }
            ,
            a.prototype.writeFloatBE = function(e, t, r) {
                return P(this, e, t, !1, r)
            }
            ,
            a.prototype.writeDoubleLE = function(e, t, r) {
                return k(this, e, t, !0, r)
            }
            ,
            a.prototype.writeDoubleBE = function(e, t, r) {
                return k(this, e, t, !1, r)
            }
            ,
            a.prototype.copy = function(e, t, r, n) {
                if (!a.isBuffer(e))
                    throw new TypeError("argument should be a Buffer");
                if (r || (r = 0),
                n || 0 === n || (n = this.length),
                t >= e.length && (t = e.length),
                t || (t = 0),
                n > 0 && n < r && (n = r),
                n === r)
                    return 0;
                if (0 === e.length || 0 === this.length)
                    return 0;
                if (t < 0)
                    throw new RangeError("targetStart out of bounds");
                if (r < 0 || r >= this.length)
                    throw new RangeError("Index out of range");
                if (n < 0)
                    throw new RangeError("sourceEnd out of bounds");
                n > this.length && (n = this.length),
                e.length - t < n - r && (n = e.length - t + r);
                var s = n - r;
                if (this === e && "function" == typeof Uint8Array.prototype.copyWithin)
                    this.copyWithin(t, r, n);
                else if (this === e && r < t && t < n)
                    for (var o = s - 1; o >= 0; --o)
                        e[o + t] = this[o + r];
                else
                    Uint8Array.prototype.set.call(e, this.subarray(r, n), t);
                return s
            }
            ,
            a.prototype.fill = function(e, t, r, n) {
                if ("string" == typeof e) {
                    if ("string" == typeof t ? (n = t,
                        t = 0,
                        r = this.length) : "string" == typeof r && (n = r,
                        r = this.length),
                    void 0 !== n && "string" != typeof n)
                        throw new TypeError("encoding must be a string");
                    if ("string" == typeof n && !a.isEncoding(n))
                        throw new TypeError("Unknown encoding: " + n);
                    if (1 === e.length) {
                        var s = e.charCodeAt(0);
                        ("utf8" === n && s < 128 || "latin1" === n) && (e = s)
                    }
                } else
                    "number" == typeof e && (e &= 255);
                if (t < 0 || this.length < t || this.length < r)
                    throw new RangeError("Out of range index");
                if (r <= t)
                    return this;
                var o;
                if (t >>>= 0,
                    r = void 0 === r ? this.length : r >>> 0,
                e || (e = 0),
                "number" == typeof e)
                    for (o = t; o < r; ++o)
                        this[o] = e;
                else {
                    var i = a.isBuffer(e) ? e : a.from(e, n)
                        , c = i.length;
                    if (0 === c)
                        throw new TypeError('The value "' + e + '" is invalid for argument "value"');
                    for (o = 0; o < r - t; ++o)
                        this[o + t] = i[o % c]
                }
                return this
            }
        ;
        var L = /[^+/0-9A-Za-z-_]/g;
        function D(e) {
            return e < 16 ? "0" + e.toString(16) : e.toString(16)
        }
        function B(e, t) {
            var r;
            t = t || 1 / 0;
            for (var n = e.length, s = null, o = [], i = 0; i < n; ++i) {
                if ((r = e.charCodeAt(i)) > 55295 && r < 57344) {
                    if (!s) {
                        if (r > 56319) {
                            (t -= 3) > -1 && o.push(239, 191, 189);
                            continue
                        }
                        if (i + 1 === n) {
                            (t -= 3) > -1 && o.push(239, 191, 189);
                            continue
                        }
                        s = r;
                        continue
                    }
                    if (r < 56320) {
                        (t -= 3) > -1 && o.push(239, 191, 189),
                            s = r;
                        continue
                    }
                    r = 65536 + (s - 55296 << 10 | r - 56320)
                } else
                    s && (t -= 3) > -1 && o.push(239, 191, 189);
                if (s = null,
                r < 128) {
                    if ((t -= 1) < 0)
                        break;
                    o.push(r)
                } else if (r < 2048) {
                    if ((t -= 2) < 0)
                        break;
                    o.push(r >> 6 | 192, 63 & r | 128)
                } else if (r < 65536) {
                    if ((t -= 3) < 0)
                        break;
                    o.push(r >> 12 | 224, r >> 6 & 63 | 128, 63 & r | 128)
                } else {
                    if (!(r < 1114112))
                        throw new Error("Invalid code point");
                    if ((t -= 4) < 0)
                        break;
                    o.push(r >> 18 | 240, r >> 12 & 63 | 128, r >> 6 & 63 | 128, 63 & r | 128)
                }
            }
            return o
        }
        function $(e) {
            return n.toByteArray(function(e) {
                if ((e = (e = e.split("=")[0]).trim().replace(L, "")).length < 2)
                    return "";
                for (; e.length % 4 != 0; )
                    e += "=";
                return e
            }(e))
        }
        function U(e, t, r, n) {
            for (var s = 0; s < n && !(s + r >= t.length || s >= e.length); ++s)
                t[s + r] = e[s];
            return s
        }
        function F(e, t) {
            return e instanceof t || null != e && null != e.constructor && null != e.constructor.name && e.constructor.name === t.name
        }
        function W(e) {
            return e != e
        }
    }
        , {
            "base64-js": 193,
            ieee754: 203
        }],
    196: [function(e, t, r) {
        var n = 1e3
            , s = 60 * n
            , o = 60 * s
            , i = 24 * o
            , a = 7 * i
            , c = 365.25 * i;
        function u(e, t, r, n) {
            var s = t >= 1.5 * r;
            return Math.round(e / r) + " " + n + (s ? "s" : "")
        }
        t.exports = function(e, t) {
            t = t || {};
            var r = typeof e;
            if ("string" === r && e.length > 0)
                return function(e) {
                    if ((e = String(e)).length > 100)
                        return;
                    var t = /^(-?(?:\d+)?\.?\d+) *(milliseconds?|msecs?|ms|seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w|years?|yrs?|y)?$/i.exec(e);
                    if (!t)
                        return;
                    var r = parseFloat(t[1]);
                    switch ((t[2] || "ms").toLowerCase()) {
                        case "years":
                        case "year":
                        case "yrs":
                        case "yr":
                        case "y":
                            return r * c;
                        case "weeks":
                        case "week":
                        case "w":
                            return r * a;
                        case "days":
                        case "day":
                        case "d":
                            return r * i;
                        case "hours":
                        case "hour":
                        case "hrs":
                        case "hr":
                        case "h":
                            return r * o;
                        case "minutes":
                        case "minute":
                        case "mins":
                        case "min":
                        case "m":
                            return r * s;
                        case "seconds":
                        case "second":
                        case "secs":
                        case "sec":
                        case "s":
                            return r * n;
                        case "milliseconds":
                        case "millisecond":
                        case "msecs":
                        case "msec":
                        case "ms":
                            return r;
                        default:
                            return
                    }
                }(e);
            if ("number" === r && isFinite(e))
                return t.long ? function(e) {
                    var t = Math.abs(e);
                    if (t >= i)
                        return u(e, t, i, "day");
                    if (t >= o)
                        return u(e, t, o, "hour");
                    if (t >= s)
                        return u(e, t, s, "minute");
                    if (t >= n)
                        return u(e, t, n, "second");
                    return e + " ms"
                }(e) : function(e) {
                    var t = Math.abs(e);
                    if (t >= i)
                        return Math.round(e / i) + "d";
                    if (t >= o)
                        return Math.round(e / o) + "h";
                    if (t >= s)
                        return Math.round(e / s) + "m";
                    if (t >= n)
                        return Math.round(e / n) + "s";
                    return e + "ms"
                }(e);
            throw new Error("val is not a non-empty string or a valid number. val=" + JSON.stringify(e))
        }
    }
        , {}],
    197: [function(e, t, r) {
        (function(n) {
                (function() {
                        r.formatArgs = function(e) {
                            if (e[0] = (this.useColors ? "%c" : "") + this.namespace + (this.useColors ? " %c" : " ") + e[0] + (this.useColors ? "%c " : " ") + "+" + t.exports.humanize(this.diff),
                                !this.useColors)
                                return;
                            const r = "color: " + this.color;
                            e.splice(1, 0, r, "color: inherit");
                            let n = 0
                                , s = 0;
                            e[0].replace(/%[a-zA-Z%]/g, (e => {
                                    "%%" !== e && (n++,
                                    "%c" === e && (s = n))
                                }
                            )),
                                e.splice(s, 0, r)
                        }
                            ,
                            r.save = function(e) {
                                try {
                                    e ? r.storage.setItem("debug", e) : r.storage.removeItem("debug")
                                } catch (e) {}
                            }
                            ,
                            r.load = function() {
                                let e;
                                try {
                                    e = r.storage.getItem("debug")
                                } catch (e) {}
                                !e && void 0 !== n && "env"in n && (e = n.env.DEBUG);
                                return e
                            }
                            ,
                            r.useColors = function() {
                                if ("undefined" != typeof window && window.process && ("renderer" === window.process.type || window.process.__nwjs))
                                    return !0;
                                if ("undefined" != typeof navigator && navigator.userAgent && navigator.userAgent.toLowerCase().match(/(edge|trident)\/(\d+)/))
                                    return !1;
                                return "undefined" != typeof document && document.documentElement && document.documentElement.style && document.documentElement.style.WebkitAppearance || "undefined" != typeof window && window.console && (window.console.firebug || window.console.exception && window.console.table) || "undefined" != typeof navigator && navigator.userAgent && navigator.userAgent.toLowerCase().match(/firefox\/(\d+)/) && parseInt(RegExp.$1, 10) >= 31 || "undefined" != typeof navigator && navigator.userAgent && navigator.userAgent.toLowerCase().match(/applewebkit\/(\d+)/)
                            }
                            ,
                            r.storage = function() {
                                try {
                                    return localStorage
                                } catch (e) {}
                            }(),
                            r.destroy = ( () => {
                                    let e = !1;
                                    return () => {
                                        e || (e = !0,
                                            console.warn("Instance method `debug.destroy()` is deprecated and no longer does anything. It will be removed in the next major version of `debug`."))
                                    }
                                }
                            )(),
                            r.colors = ["#0000CC", "#0000FF", "#0033CC", "#0033FF", "#0066CC", "#0066FF", "#0099CC", "#0099FF", "#00CC00", "#00CC33", "#00CC66", "#00CC99", "#00CCCC", "#00CCFF", "#3300CC", "#3300FF", "#3333CC", "#3333FF", "#3366CC", "#3366FF", "#3399CC", "#3399FF", "#33CC00", "#33CC33", "#33CC66", "#33CC99", "#33CCCC", "#33CCFF", "#6600CC", "#6600FF", "#6633CC", "#6633FF", "#66CC00", "#66CC33", "#9900CC", "#9900FF", "#9933CC", "#9933FF", "#99CC00", "#99CC33", "#CC0000", "#CC0033", "#CC0066", "#CC0099", "#CC00CC", "#CC00FF", "#CC3300", "#CC3333", "#CC3366", "#CC3399", "#CC33CC", "#CC33FF", "#CC6600", "#CC6633", "#CC9900", "#CC9933", "#CCCC00", "#CCCC33", "#FF0000", "#FF0033", "#FF0066", "#FF0099", "#FF00CC", "#FF00FF", "#FF3300", "#FF3333", "#FF3366", "#FF3399", "#FF33CC", "#FF33FF", "#FF6600", "#FF6633", "#FF9900", "#FF9933", "#FFCC00", "#FFCC33"],
                            r.log = console.debug || console.log || ( () => {}
                            ),
                            t.exports = e("./common")(r);
                        const {formatters: s} = t.exports;
                        s.j = function(e) {
                            try {
                                return JSON.stringify(e)
                            } catch (e) {
                                return "[UnexpectedJSONParseError]: " + e.message
                            }
                        }
                    }
                ).call(this)
            }
        ).call(this, e("_process"))
    }
        , {
            "./common": 198,
            _process: 211
        }],
    198: [function(e, t, r) {
        t.exports = function(t) {
            function r(e) {
                let t, s, o, i = null;
                function a(...e) {
                    if (!a.enabled)
                        return;
                    const n = a
                        , s = Number(new Date)
                        , o = s - (t || s);
                    n.diff = o,
                        n.prev = t,
                        n.curr = s,
                        t = s,
                        e[0] = r.coerce(e[0]),
                    "string" != typeof e[0] && e.unshift("%O");
                    let i = 0;
                    e[0] = e[0].replace(/%([a-zA-Z%])/g, ( (t, s) => {
                            if ("%%" === t)
                                return "%";
                            i++;
                            const o = r.formatters[s];
                            if ("function" == typeof o) {
                                const r = e[i];
                                t = o.call(n, r),
                                    e.splice(i, 1),
                                    i--
                            }
                            return t
                        }
                    )),
                        r.formatArgs.call(n, e);
                    (n.log || r.log).apply(n, e)
                }
                return a.namespace = e,
                    a.useColors = r.useColors(),
                    a.color = r.selectColor(e),
                    a.extend = n,
                    a.destroy = r.destroy,
                    Object.defineProperty(a, "enabled", {
                        enumerable: !0,
                        configurable: !1,
                        get: () => null !== i ? i : (s !== r.namespaces && (s = r.namespaces,
                            o = r.enabled(e)),
                            o),
                        set: e => {
                            i = e
                        }
                    }),
                "function" == typeof r.init && r.init(a),
                    a
            }
            function n(e, t) {
                const n = r(this.namespace + (void 0 === t ? ":" : t) + e);
                return n.log = this.log,
                    n
            }
            function s(e) {
                return e.toString().substring(2, e.toString().length - 2).replace(/\.\*\?$/, "*")
            }
            return r.debug = r,
                r.default = r,
                r.coerce = function(e) {
                    if (e instanceof Error)
                        return e.stack || e.message;
                    return e
                }
                ,
                r.disable = function() {
                    const e = [...r.names.map(s), ...r.skips.map(s).map((e => "-" + e))].join(",");
                    return r.enable(""),
                        e
                }
                ,
                r.enable = function(e) {
                    let t;
                    r.save(e),
                        r.namespaces = e,
                        r.names = [],
                        r.skips = [];
                    const n = ("string" == typeof e ? e : "").split(/[\s,]+/)
                        , s = n.length;
                    for (t = 0; t < s; t++)
                        n[t] && ("-" === (e = n[t].replace(/\*/g, ".*?"))[0] ? r.skips.push(new RegExp("^" + e.slice(1) + "$")) : r.names.push(new RegExp("^" + e + "$")))
                }
                ,
                r.enabled = function(e) {
                    if ("*" === e[e.length - 1])
                        return !0;
                    let t, n;
                    for (t = 0,
                             n = r.skips.length; t < n; t++)
                        if (r.skips[t].test(e))
                            return !1;
                    for (t = 0,
                             n = r.names.length; t < n; t++)
                        if (r.names[t].test(e))
                            return !0;
                    return !1
                }
                ,
                r.humanize = e("ms"),
                r.destroy = function() {
                    console.warn("Instance method `debug.destroy()` is deprecated and no longer does anything. It will be removed in the next major version of `debug`.")
                }
                ,
                Object.keys(t).forEach((e => {
                        r[e] = t[e]
                    }
                )),
                r.names = [],
                r.skips = [],
                r.formatters = {},
                r.selectColor = function(e) {
                    let t = 0;
                    for (let r = 0; r < e.length; r++)
                        t = (t << 5) - t + e.charCodeAt(r),
                            t |= 0;
                    return r.colors[Math.abs(t) % r.colors.length]
                }
                ,
                r.enable(r.load()),
                r
        }
    }
        , {
            ms: 196
        }],
    199: [function(e, t, r) {
        (function(e) {
                (function() {
                        "use strict";
                        var t = this && this.__spreadArrays || function() {
                                for (var e = 0, t = 0, r = arguments.length; t < r; t++)
                                    e += arguments[t].length;
                                var n = Array(e)
                                    , s = 0;
                                for (t = 0; t < r; t++)
                                    for (var o = arguments[t], i = 0, a = o.length; i < a; i++,
                                        s++)
                                        n[s] = o[i];
                                return n
                            }
                        ;
                        Object.defineProperty(r, "__esModule", {
                            value: !0
                        });
                        var n = function(e, t, r) {
                            this.name = e,
                                this.version = t,
                                this.os = r,
                                this.type = "browser"
                        };
                        r.BrowserInfo = n;
                        var s = function(t) {
                            this.version = t,
                                this.type = "node",
                                this.name = "node",
                                this.os = e.platform
                        };
                        r.NodeInfo = s;
                        var o = function(e, t, r, n) {
                            this.name = e,
                                this.version = t,
                                this.os = r,
                                this.bot = n,
                                this.type = "bot-device"
                        };
                        r.SearchBotDeviceInfo = o;
                        var i = function() {
                            this.type = "bot",
                                this.bot = !0,
                                this.name = "bot",
                                this.version = null,
                                this.os = null
                        };
                        r.BotInfo = i;
                        var a = function() {
                            this.type = "react-native",
                                this.name = "react-native",
                                this.version = null,
                                this.os = null
                        };
                        r.ReactNativeInfo = a;
                        var c = /(nuhk|Googlebot|Yammybot|Openbot|Slurp|MSNBot|Ask\ Jeeves\/Teoma|ia_archiver)/
                            , u = 3
                            , l = [["aol", /AOLShield\/([0-9\._]+)/], ["edge", /Edge\/([0-9\._]+)/], ["edge-ios", /EdgiOS\/([0-9\._]+)/], ["yandexbrowser", /YaBrowser\/([0-9\._]+)/], ["kakaotalk", /KAKAOTALK\s([0-9\.]+)/], ["samsung", /SamsungBrowser\/([0-9\.]+)/], ["silk", /\bSilk\/([0-9._-]+)\b/], ["miui", /MiuiBrowser\/([0-9\.]+)$/], ["beaker", /BeakerBrowser\/([0-9\.]+)/], ["edge-chromium", /EdgA?\/([0-9\.]+)/], ["chromium-webview", /(?!Chrom.*OPR)wv\).*Chrom(?:e|ium)\/([0-9\.]+)(:?\s|$)/], ["chrome", /(?!Chrom.*OPR)Chrom(?:e|ium)\/([0-9\.]+)(:?\s|$)/], ["phantomjs", /PhantomJS\/([0-9\.]+)(:?\s|$)/], ["crios", /CriOS\/([0-9\.]+)(:?\s|$)/], ["firefox", /Firefox\/([0-9\.]+)(?:\s|$)/], ["fxios", /FxiOS\/([0-9\.]+)/], ["opera-mini", /Opera Mini.*Version\/([0-9\.]+)/], ["opera", /Opera\/([0-9\.]+)(?:\s|$)/], ["opera", /OPR\/([0-9\.]+)(:?\s|$)/], ["ie", /Trident\/7\.0.*rv\:([0-9\.]+).*\).*Gecko$/], ["ie", /MSIE\s([0-9\.]+);.*Trident\/[4-7].0/], ["ie", /MSIE\s(7\.0)/], ["bb10", /BB10;\sTouch.*Version\/([0-9\.]+)/], ["android", /Android\s([0-9\.]+)/], ["ios", /Version\/([0-9\._]+).*Mobile.*Safari.*/], ["safari", /Version\/([0-9\._]+).*Safari/], ["facebook", /FBAV\/([0-9\.]+)/], ["instagram", /Instagram\s([0-9\.]+)/], ["ios-webview", /AppleWebKit\/([0-9\.]+).*Mobile/], ["ios-webview", /AppleWebKit\/([0-9\.]+).*Gecko\)$/], ["searchbot", /alexa|bot|crawl(er|ing)|facebookexternalhit|feedburner|google web preview|nagios|postrank|pingdom|slurp|spider|yahoo!|yandex/]]
                            , d = [["iOS", /iP(hone|od|ad)/], ["Android OS", /Android/], ["BlackBerry OS", /BlackBerry|BB10/], ["Windows Mobile", /IEMobile/], ["Amazon OS", /Kindle/], ["Windows 3.11", /Win16/], ["Windows 95", /(Windows 95)|(Win95)|(Windows_95)/], ["Windows 98", /(Windows 98)|(Win98)/], ["Windows 2000", /(Windows NT 5.0)|(Windows 2000)/], ["Windows XP", /(Windows NT 5.1)|(Windows XP)/], ["Windows Server 2003", /(Windows NT 5.2)/], ["Windows Vista", /(Windows NT 6.0)/], ["Windows 7", /(Windows NT 6.1)/], ["Windows 8", /(Windows NT 6.2)/], ["Windows 8.1", /(Windows NT 6.3)/], ["Windows 10", /(Windows NT 10.0)/], ["Windows ME", /Windows ME/], ["Open BSD", /OpenBSD/], ["Sun OS", /SunOS/], ["Chrome OS", /CrOS/], ["Linux", /(Linux)|(X11)/], ["Mac OS", /(Mac_PowerPC)|(Macintosh)/], ["QNX", /QNX/], ["BeOS", /BeOS/], ["OS/2", /OS\/2/]];
                        function f(e) {
                            return "" !== e && l.reduce((function(t, r) {
                                    var n = r[0]
                                        , s = r[1];
                                    if (t)
                                        return t;
                                    var o = s.exec(e);
                                    return !!o && [n, o]
                                }
                            ), !1)
                        }
                        function p(e) {
                            var r = f(e);
                            if (!r)
                                return null;
                            var s = r[0]
                                , a = r[1];
                            if ("searchbot" === s)
                                return new i;
                            var l = a[1] && a[1].split(/[._]/).slice(0, 3);
                            l ? l.length < u && (l = t(l, function(e) {
                                for (var t = [], r = 0; r < e; r++)
                                    t.push("0");
                                return t
                            }(u - l.length))) : l = [];
                            var d = l.join(".")
                                , p = h(e)
                                , g = c.exec(e);
                            return g && g[1] ? new o(s,d,p,g[1]) : new n(s,d,p)
                        }
                        function h(e) {
                            for (var t = 0, r = d.length; t < r; t++) {
                                var n = d[t]
                                    , s = n[0];
                                if (n[1].exec(e))
                                    return s
                            }
                            return null
                        }
                        function g() {
                            return void 0 !== e && e.version ? new s(e.version.slice(1)) : null
                        }
                        r.detect = function(e) {
                            return e ? p(e) : "undefined" == typeof document && "undefined" != typeof navigator && "ReactNative" === navigator.product ? new a : "undefined" != typeof navigator ? p(navigator.userAgent) : g()
                        }
                            ,
                            r.browserName = function(e) {
                                var t = f(e);
                                return t ? t[0] : null
                            }
                            ,
                            r.parseUserAgent = p,
                            r.detectOS = h,
                            r.getNodeVersion = g
                    }
                ).call(this)
            }
        ).call(this, e("_process"))
    }
        , {
            _process: 211
        }],
    200: [function(e, t, r) {
        "use strict";
        var n, s = "object" == typeof Reflect ? Reflect : null, o = s && "function" == typeof s.apply ? s.apply : function(e, t, r) {
                return Function.prototype.apply.call(e, t, r)
            }
        ;
        n = s && "function" == typeof s.ownKeys ? s.ownKeys : Object.getOwnPropertySymbols ? function(e) {
                return Object.getOwnPropertyNames(e).concat(Object.getOwnPropertySymbols(e))
            }
            : function(e) {
                return Object.getOwnPropertyNames(e)
            }
        ;
        var i = Number.isNaN || function(e) {
                return e != e
            }
        ;
        function a() {
            a.init.call(this)
        }
        t.exports = a,
            t.exports.once = function(e, t) {
                return new Promise((function(r, n) {
                        function s(r) {
                            e.removeListener(t, o),
                                n(r)
                        }
                        function o() {
                            "function" == typeof e.removeListener && e.removeListener("error", s),
                                r([].slice.call(arguments))
                        }
                        b(e, t, o, {
                            once: !0
                        }),
                        "error" !== t && function(e, t, r) {
                            "function" == typeof e.on && b(e, "error", t, r)
                        }(e, s, {
                            once: !0
                        })
                    }
                ))
            }
            ,
            a.EventEmitter = a,
            a.prototype._events = void 0,
            a.prototype._eventsCount = 0,
            a.prototype._maxListeners = void 0;
        var c = 10;
        function u(e) {
            if ("function" != typeof e)
                throw new TypeError('The "listener" argument must be of type Function. Received type ' + typeof e)
        }
        function l(e) {
            return void 0 === e._maxListeners ? a.defaultMaxListeners : e._maxListeners
        }
        function d(e, t, r, n) {
            var s, o, i, a;
            if (u(r),
                void 0 === (o = e._events) ? (o = e._events = Object.create(null),
                    e._eventsCount = 0) : (void 0 !== o.newListener && (e.emit("newListener", t, r.listener ? r.listener : r),
                    o = e._events),
                    i = o[t]),
            void 0 === i)
                i = o[t] = r,
                    ++e._eventsCount;
            else if ("function" == typeof i ? i = o[t] = n ? [r, i] : [i, r] : n ? i.unshift(r) : i.push(r),
            (s = l(e)) > 0 && i.length > s && !i.warned) {
                i.warned = !0;
                var c = new Error("Possible EventEmitter memory leak detected. " + i.length + " " + String(t) + " listeners added. Use emitter.setMaxListeners() to increase limit");
                c.name = "MaxListenersExceededWarning",
                    c.emitter = e,
                    c.type = t,
                    c.count = i.length,
                    a = c,
                console && console.warn && console.warn(a)
            }
            return e
        }
        function f() {
            if (!this.fired)
                return this.target.removeListener(this.type, this.wrapFn),
                    this.fired = !0,
                    0 === arguments.length ? this.listener.call(this.target) : this.listener.apply(this.target, arguments)
        }
        function p(e, t, r) {
            var n = {
                fired: !1,
                wrapFn: void 0,
                target: e,
                type: t,
                listener: r
            }
                , s = f.bind(n);
            return s.listener = r,
                n.wrapFn = s,
                s
        }
        function h(e, t, r) {
            var n = e._events;
            if (void 0 === n)
                return [];
            var s = n[t];
            return void 0 === s ? [] : "function" == typeof s ? r ? [s.listener || s] : [s] : r ? function(e) {
                for (var t = new Array(e.length), r = 0; r < t.length; ++r)
                    t[r] = e[r].listener || e[r];
                return t
            }(s) : m(s, s.length)
        }
        function g(e) {
            var t = this._events;
            if (void 0 !== t) {
                var r = t[e];
                if ("function" == typeof r)
                    return 1;
                if (void 0 !== r)
                    return r.length
            }
            return 0
        }
        function m(e, t) {
            for (var r = new Array(t), n = 0; n < t; ++n)
                r[n] = e[n];
            return r
        }
        function b(e, t, r, n) {
            if ("function" == typeof e.on)
                n.once ? e.once(t, r) : e.on(t, r);
            else {
                if ("function" != typeof e.addEventListener)
                    throw new TypeError('The "emitter" argument must be of type EventEmitter. Received type ' + typeof e);
                e.addEventListener(t, (function s(o) {
                        n.once && e.removeEventListener(t, s),
                            r(o)
                    }
                ))
            }
        }
        Object.defineProperty(a, "defaultMaxListeners", {
            enumerable: !0,
            get: function() {
                return c
            },
            set: function(e) {
                if ("number" != typeof e || e < 0 || i(e))
                    throw new RangeError('The value of "defaultMaxListeners" is out of range. It must be a non-negative number. Received ' + e + ".");
                c = e
            }
        }),
            a.init = function() {
                void 0 !== this._events && this._events !== Object.getPrototypeOf(this)._events || (this._events = Object.create(null),
                    this._eventsCount = 0),
                    this._maxListeners = this._maxListeners || void 0
            }
            ,
            a.prototype.setMaxListeners = function(e) {
                if ("number" != typeof e || e < 0 || i(e))
                    throw new RangeError('The value of "n" is out of range. It must be a non-negative number. Received ' + e + ".");
                return this._maxListeners = e,
                    this
            }
            ,
            a.prototype.getMaxListeners = function() {
                return l(this)
            }
            ,
            a.prototype.emit = function(e) {
                for (var t = [], r = 1; r < arguments.length; r++)
                    t.push(arguments[r]);
                var n = "error" === e
                    , s = this._events;
                if (void 0 !== s)
                    n = n && void 0 === s.error;
                else if (!n)
                    return !1;
                if (n) {
                    var i;
                    if (t.length > 0 && (i = t[0]),
                    i instanceof Error)
                        throw i;
                    var a = new Error("Unhandled error." + (i ? " (" + i.message + ")" : ""));
                    throw a.context = i,
                        a
                }
                var c = s[e];
                if (void 0 === c)
                    return !1;
                if ("function" == typeof c)
                    o(c, this, t);
                else {
                    var u = c.length
                        , l = m(c, u);
                    for (r = 0; r < u; ++r)
                        o(l[r], this, t)
                }
                return !0
            }
            ,
            a.prototype.addListener = function(e, t) {
                return d(this, e, t, !1)
            }
            ,
            a.prototype.on = a.prototype.addListener,
            a.prototype.prependListener = function(e, t) {
                return d(this, e, t, !0)
            }
            ,
            a.prototype.once = function(e, t) {
                return u(t),
                    this.on(e, p(this, e, t)),
                    this
            }
            ,
            a.prototype.prependOnceListener = function(e, t) {
                return u(t),
                    this.prependListener(e, p(this, e, t)),
                    this
            }
            ,
            a.prototype.removeListener = function(e, t) {
                var r, n, s, o, i;
                if (u(t),
                void 0 === (n = this._events))
                    return this;
                if (void 0 === (r = n[e]))
                    return this;
                if (r === t || r.listener === t)
                    0 == --this._eventsCount ? this._events = Object.create(null) : (delete n[e],
                    n.removeListener && this.emit("removeListener", e, r.listener || t));
                else if ("function" != typeof r) {
                    for (s = -1,
                             o = r.length - 1; o >= 0; o--)
                        if (r[o] === t || r[o].listener === t) {
                            i = r[o].listener,
                                s = o;
                            break
                        }
                    if (s < 0)
                        return this;
                    0 === s ? r.shift() : function(e, t) {
                        for (; t + 1 < e.length; t++)
                            e[t] = e[t + 1];
                        e.pop()
                    }(r, s),
                    1 === r.length && (n[e] = r[0]),
                    void 0 !== n.removeListener && this.emit("removeListener", e, i || t)
                }
                return this
            }
            ,
            a.prototype.off = a.prototype.removeListener,
            a.prototype.removeAllListeners = function(e) {
                var t, r, n;
                if (void 0 === (r = this._events))
                    return this;
                if (void 0 === r.removeListener)
                    return 0 === arguments.length ? (this._events = Object.create(null),
                        this._eventsCount = 0) : void 0 !== r[e] && (0 == --this._eventsCount ? this._events = Object.create(null) : delete r[e]),
                        this;
                if (0 === arguments.length) {
                    var s, o = Object.keys(r);
                    for (n = 0; n < o.length; ++n)
                        "removeListener" !== (s = o[n]) && this.removeAllListeners(s);
                    return this.removeAllListeners("removeListener"),
                        this._events = Object.create(null),
                        this._eventsCount = 0,
                        this
                }
                if ("function" == typeof (t = r[e]))
                    this.removeListener(e, t);
                else if (void 0 !== t)
                    for (n = t.length - 1; n >= 0; n--)
                        this.removeListener(e, t[n]);
                return this
            }
            ,
            a.prototype.listeners = function(e) {
                return h(this, e, !0)
            }
            ,
            a.prototype.rawListeners = function(e) {
                return h(this, e, !1)
            }
            ,
            a.listenerCount = function(e, t) {
                return "function" == typeof e.listenerCount ? e.listenerCount(t) : g.call(e, t)
            }
            ,
            a.prototype.listenerCount = g,
            a.prototype.eventNames = function() {
                return this._eventsCount > 0 ? n(this._events) : []
            }
    }
        , {}],
    201: [function(e, t, r) {
        "use strict";
        t.exports = function e(t, r) {
            if (t === r)
                return !0;
            if (t && r && "object" == typeof t && "object" == typeof r) {
                if (t.constructor !== r.constructor)
                    return !1;
                var n, s, o;
                if (Array.isArray(t)) {
                    if ((n = t.length) != r.length)
                        return !1;
                    for (s = n; 0 != s--; )
                        if (!e(t[s], r[s]))
                            return !1;
                    return !0
                }
                if (t.constructor === RegExp)
                    return t.source === r.source && t.flags === r.flags;
                if (t.valueOf !== Object.prototype.valueOf)
                    return t.valueOf() === r.valueOf();
                if (t.toString !== Object.prototype.toString)
                    return t.toString() === r.toString();
                if ((n = (o = Object.keys(t)).length) !== Object.keys(r).length)
                    return !1;
                for (s = n; 0 != s--; )
                    if (!Object.prototype.hasOwnProperty.call(r, o[s]))
                        return !1;
                for (s = n; 0 != s--; ) {
                    var i = o[s];
                    if (!e(t[i], r[i]))
                        return !1
                }
                return !0
            }
            return t != t && r != r
        }
    }
        , {}],
    202: [function(e, t, r) {
        t.exports = c,
            c.default = c,
            c.stable = f,
            c.stableStringify = f;
        var n = "[...]"
            , s = "[Circular]"
            , o = []
            , i = [];
        function a() {
            return {
                depthLimit: Number.MAX_SAFE_INTEGER,
                edgesLimit: Number.MAX_SAFE_INTEGER
            }
        }
        function c(e, t, r, n) {
            var s;
            void 0 === n && (n = a()),
                l(e, "", 0, [], void 0, 0, n);
            try {
                s = 0 === i.length ? JSON.stringify(e, t, r) : JSON.stringify(e, h(t), r)
            } catch (e) {
                return JSON.stringify("[unable to serialize, circular reference is too complex to analyze]")
            } finally {
                for (; 0 !== o.length; ) {
                    var c = o.pop();
                    4 === c.length ? Object.defineProperty(c[0], c[1], c[3]) : c[0][c[1]] = c[2]
                }
            }
            return s
        }
        function u(e, t, r, n) {
            var s = Object.getOwnPropertyDescriptor(n, r);
            void 0 !== s.get ? s.configurable ? (Object.defineProperty(n, r, {
                value: e
            }),
                o.push([n, r, t, s])) : i.push([t, r, e]) : (n[r] = e,
                o.push([n, r, t]))
        }
        function l(e, t, r, o, i, a, c) {
            var d;
            if (a += 1,
            "object" == typeof e && null !== e) {
                for (d = 0; d < o.length; d++)
                    if (o[d] === e)
                        return void u(s, e, t, i);
                if (void 0 !== c.depthLimit && a > c.depthLimit)
                    return void u(n, e, t, i);
                if (void 0 !== c.edgesLimit && r + 1 > c.edgesLimit)
                    return void u(n, e, t, i);
                if (o.push(e),
                    Array.isArray(e))
                    for (d = 0; d < e.length; d++)
                        l(e[d], d, d, o, e, a, c);
                else {
                    var f = Object.keys(e);
                    for (d = 0; d < f.length; d++) {
                        var p = f[d];
                        l(e[p], p, d, o, e, a, c)
                    }
                }
                o.pop()
            }
        }
        function d(e, t) {
            return e < t ? -1 : e > t ? 1 : 0
        }
        function f(e, t, r, n) {
            void 0 === n && (n = a());
            var s, c = p(e, "", 0, [], void 0, 0, n) || e;
            try {
                s = 0 === i.length ? JSON.stringify(c, t, r) : JSON.stringify(c, h(t), r)
            } catch (e) {
                return JSON.stringify("[unable to serialize, circular reference is too complex to analyze]")
            } finally {
                for (; 0 !== o.length; ) {
                    var u = o.pop();
                    4 === u.length ? Object.defineProperty(u[0], u[1], u[3]) : u[0][u[1]] = u[2]
                }
            }
            return s
        }
        function p(e, t, r, i, a, c, l) {
            var f;
            if (c += 1,
            "object" == typeof e && null !== e) {
                for (f = 0; f < i.length; f++)
                    if (i[f] === e)
                        return void u(s, e, t, a);
                try {
                    if ("function" == typeof e.toJSON)
                        return
                } catch (e) {
                    return
                }
                if (void 0 !== l.depthLimit && c > l.depthLimit)
                    return void u(n, e, t, a);
                if (void 0 !== l.edgesLimit && r + 1 > l.edgesLimit)
                    return void u(n, e, t, a);
                if (i.push(e),
                    Array.isArray(e))
                    for (f = 0; f < e.length; f++)
                        p(e[f], f, f, i, e, c, l);
                else {
                    var h = {}
                        , g = Object.keys(e).sort(d);
                    for (f = 0; f < g.length; f++) {
                        var m = g[f];
                        p(e[m], m, f, i, e, c, l),
                            h[m] = e[m]
                    }
                    if (void 0 === a)
                        return h;
                    o.push([a, t, e]),
                        a[t] = h
                }
                i.pop()
            }
        }
        function h(e) {
            return e = void 0 !== e ? e : function(e, t) {
                return t
            }
                ,
                function(t, r) {
                    if (i.length > 0)
                        for (var n = 0; n < i.length; n++) {
                            var s = i[n];
                            if (s[1] === t && s[0] === r) {
                                r = s[2],
                                    i.splice(n, 1);
                                break
                            }
                        }
                    return e.call(this, t, r)
                }
        }
    }
        , {}],
    203: [function(e, t, r) {
        /*! ieee754. BSD-3-Clause License. Feross Aboukhadijeh <https://feross.org/opensource> */
        r.read = function(e, t, r, n, s) {
            var o, i, a = 8 * s - n - 1, c = (1 << a) - 1, u = c >> 1, l = -7, d = r ? s - 1 : 0, f = r ? -1 : 1, p = e[t + d];
            for (d += f,
                     o = p & (1 << -l) - 1,
                     p >>= -l,
                     l += a; l > 0; o = 256 * o + e[t + d],
                     d += f,
                     l -= 8)
                ;
            for (i = o & (1 << -l) - 1,
                     o >>= -l,
                     l += n; l > 0; i = 256 * i + e[t + d],
                     d += f,
                     l -= 8)
                ;
            if (0 === o)
                o = 1 - u;
            else {
                if (o === c)
                    return i ? NaN : 1 / 0 * (p ? -1 : 1);
                i += Math.pow(2, n),
                    o -= u
            }
            return (p ? -1 : 1) * i * Math.pow(2, o - n)
        }
            ,
            r.write = function(e, t, r, n, s, o) {
                var i, a, c, u = 8 * o - s - 1, l = (1 << u) - 1, d = l >> 1, f = 23 === s ? Math.pow(2, -24) - Math.pow(2, -77) : 0, p = n ? 0 : o - 1, h = n ? 1 : -1, g = t < 0 || 0 === t && 1 / t < 0 ? 1 : 0;
                for (t = Math.abs(t),
                         isNaN(t) || t === 1 / 0 ? (a = isNaN(t) ? 1 : 0,
                             i = l) : (i = Math.floor(Math.log(t) / Math.LN2),
                         t * (c = Math.pow(2, -i)) < 1 && (i--,
                             c *= 2),
                         (t += i + d >= 1 ? f / c : f * Math.pow(2, 1 - d)) * c >= 2 && (i++,
                             c /= 2),
                             i + d >= l ? (a = 0,
                                 i = l) : i + d >= 1 ? (a = (t * c - 1) * Math.pow(2, s),
                                 i += d) : (a = t * Math.pow(2, d - 1) * Math.pow(2, s),
                                 i = 0)); s >= 8; e[r + p] = 255 & a,
                         p += h,
                         a /= 256,
                         s -= 8)
                    ;
                for (i = i << s | a,
                         u += s; u > 0; e[r + p] = 255 & i,
                         p += h,
                         i /= 256,
                         u -= 8)
                    ;
                e[r + p - h] |= 128 * g
            }
    }
        , {}],
    204: [function(e, t, r) {
        "function" == typeof Object.create ? t.exports = function(e, t) {
                t && (e.super_ = t,
                    e.prototype = Object.create(t.prototype, {
                        constructor: {
                            value: e,
                            enumerable: !1,
                            writable: !0,
                            configurable: !0
                        }
                    }))
            }
            : t.exports = function(e, t) {
                if (t) {
                    e.super_ = t;
                    var r = function() {};
                    r.prototype = t.prototype,
                        e.prototype = new r,
                        e.prototype.constructor = e
                }
            }
    }
        , {}],
    205: [function(e, t, r) {
        "use strict";
        const n = e => null !== e && "object" == typeof e && "function" == typeof e.pipe;
        n.writable = e => n(e) && !1 !== e.writable && "function" == typeof e._write && "object" == typeof e._writableState,
            n.readable = e => n(e) && !1 !== e.readable && "function" == typeof e._read && "object" == typeof e._readableState,
            n.duplex = e => n.writable(e) && n.readable(e),
            n.transform = e => n.duplex(e) && "function" == typeof e._transform && "object" == typeof e._transformState,
            t.exports = n
    }
        , {}],
    206: [function(e, t, r) {
        !function(e, r) {
            "use strict";
            "function" == typeof define && define.amd ? define(r) : "object" == typeof t && t.exports ? t.exports = r() : e.log = r()
        }(this, (function() {
                "use strict";
                var e = function() {}
                    , t = "undefined"
                    , r = typeof window !== t && typeof window.navigator !== t && /Trident\/|MSIE /.test(window.navigator.userAgent)
                    , n = ["trace", "debug", "info", "warn", "error"]
                    , s = {}
                    , o = null;
                function i(e, t) {
                    var r = e[t];
                    if ("function" == typeof r.bind)
                        return r.bind(e);
                    try {
                        return Function.prototype.bind.call(r, e)
                    } catch (t) {
                        return function() {
                            return Function.prototype.apply.apply(r, [e, arguments])
                        }
                    }
                }
                function a() {
                    console.log && (console.log.apply ? console.log.apply(console, arguments) : Function.prototype.apply.apply(console.log, [console, arguments])),
                    console.trace && console.trace()
                }
                function c() {
                    for (var r = this.getLevel(), s = 0; s < n.length; s++) {
                        var o = n[s];
                        this[o] = s < r ? e : this.methodFactory(o, r, this.name)
                    }
                    if (this.log = this.debug,
                    typeof console === t && r < this.levels.SILENT)
                        return "No console available for logging"
                }
                function u(e) {
                    return function() {
                        typeof console !== t && (c.call(this),
                            this[e].apply(this, arguments))
                    }
                }
                function l(n, s, o) {
                    return function(n) {
                        return "debug" === n && (n = "log"),
                        typeof console !== t && ("trace" === n && r ? a : void 0 !== console[n] ? i(console, n) : void 0 !== console.log ? i(console, "log") : e)
                    }(n) || u.apply(this, arguments)
                }
                function d(e, r) {
                    var i, a, u, d = this, f = "loglevel";
                    function p() {
                        var e;
                        if (typeof window !== t && f) {
                            try {
                                e = window.localStorage[f]
                            } catch (e) {}
                            if (typeof e === t)
                                try {
                                    var r = window.document.cookie
                                        , n = encodeURIComponent(f)
                                        , s = r.indexOf(n + "=");
                                    -1 !== s && (e = /^([^;]+)/.exec(r.slice(s + n.length + 1))[1])
                                } catch (e) {}
                            return void 0 === d.levels[e] && (e = void 0),
                                e
                        }
                    }
                    function h(e) {
                        var t = e;
                        if ("string" == typeof t && void 0 !== d.levels[t.toUpperCase()] && (t = d.levels[t.toUpperCase()]),
                        "number" == typeof t && t >= 0 && t <= d.levels.SILENT)
                            return t;
                        throw new TypeError("log.setLevel() called with invalid level: " + e)
                    }
                    "string" == typeof e ? f += ":" + e : "symbol" == typeof e && (f = void 0),
                        d.name = e,
                        d.levels = {
                            TRACE: 0,
                            DEBUG: 1,
                            INFO: 2,
                            WARN: 3,
                            ERROR: 4,
                            SILENT: 5
                        },
                        d.methodFactory = r || l,
                        d.getLevel = function() {
                            return null != u ? u : null != a ? a : i
                        }
                        ,
                        d.setLevel = function(e, r) {
                            return u = h(e),
                            !1 !== r && function(e) {
                                var r = (n[e] || "silent").toUpperCase();
                                if (typeof window !== t && f) {
                                    try {
                                        return void (window.localStorage[f] = r)
                                    } catch (e) {}
                                    try {
                                        window.document.cookie = encodeURIComponent(f) + "=" + r + ";"
                                    } catch (e) {}
                                }
                            }(u),
                                c.call(d)
                        }
                        ,
                        d.setDefaultLevel = function(e) {
                            a = h(e),
                            p() || d.setLevel(e, !1)
                        }
                        ,
                        d.resetLevel = function() {
                            u = null,
                                function() {
                                    if (typeof window !== t && f) {
                                        try {
                                            window.localStorage.removeItem(f)
                                        } catch (e) {}
                                        try {
                                            window.document.cookie = encodeURIComponent(f) + "=; expires=Thu, 01 Jan 1970 00:00:00 UTC"
                                        } catch (e) {}
                                    }
                                }(),
                                c.call(d)
                        }
                        ,
                        d.enableAll = function(e) {
                            d.setLevel(d.levels.TRACE, e)
                        }
                        ,
                        d.disableAll = function(e) {
                            d.setLevel(d.levels.SILENT, e)
                        }
                        ,
                        d.rebuild = function() {
                            if (o !== d && (i = h(o.getLevel())),
                                c.call(d),
                            o === d)
                                for (var e in s)
                                    s[e].rebuild()
                        }
                        ,
                        i = h(o ? o.getLevel() : "WARN");
                    var g = p();
                    null != g && (u = h(g)),
                        c.call(d)
                }
                (o = new d).getLogger = function(e) {
                    if ("symbol" != typeof e && "string" != typeof e || "" === e)
                        throw new TypeError("You must supply a name when creating a logger.");
                    var t = s[e];
                    return t || (t = s[e] = new d(e,o.methodFactory)),
                        t
                }
                ;
                var f = typeof window !== t ? window.log : void 0;
                return o.noConflict = function() {
                    return typeof window !== t && window.log === o && (window.log = f),
                        o
                }
                    ,
                    o.getLoggers = function() {
                        return s
                    }
                    ,
                    o.default = o,
                    o
            }
        ))
    }
        , {}],
    207: [function(e, t, r) {
        var n = e("wrappy");
        function s(e) {
            var t = function() {
                return t.called ? t.value : (t.called = !0,
                    t.value = e.apply(this, arguments))
            };
            return t.called = !1,
                t
        }
        function o(e) {
            var t = function() {
                if (t.called)
                    throw new Error(t.onceError);
                return t.called = !0,
                    t.value = e.apply(this, arguments)
            }
                , r = e.name || "Function wrapped with `once`";
            return t.onceError = r + " shouldn't be called more than once",
                t.called = !1,
                t
        }
        t.exports = n(s),
            t.exports.strict = n(o),
            s.proto = s((function() {
                    Object.defineProperty(Function.prototype, "once", {
                        value: function() {
                            return s(this)
                        },
                        configurable: !0
                    }),
                        Object.defineProperty(Function.prototype, "onceStrict", {
                            value: function() {
                                return o(this)
                            },
                            configurable: !0
                        })
                }
            ))
    }
        , {
            wrappy: 290
        }],
    208: [function(e, t, r) {
        "use strict";
        const {ErrorWithCause: n} = e("./lib/error-with-cause")
            , {findCauseByReference: s, getErrorCause: o, messageWithCauses: i, stackWithCauses: a} = e("./lib/helpers");
        t.exports = {
            ErrorWithCause: n,
            findCauseByReference: s,
            getErrorCause: o,
            stackWithCauses: a,
            messageWithCauses: i
        }
    }
        , {
            "./lib/error-with-cause": 209,
            "./lib/helpers": 210
        }],
    209: [function(e, t, r) {
        "use strict";
        class n extends Error {
            constructor(e, {cause: t}={}) {
                super(e),
                    this.name = n.name,
                t && (this.cause = t),
                    this.message = e
            }
        }
        t.exports = {
            ErrorWithCause: n
        }
    }
        , {}],
    210: [function(e, t, r) {
        "use strict";
        const n = e => {
                if (e && "object" == typeof e && "cause"in e) {
                    if ("function" == typeof e.cause) {
                        const t = e.cause();
                        return t instanceof Error ? t : void 0
                    }
                    return e.cause instanceof Error ? e.cause : void 0
                }
            }
            , s = (e, t) => {
                if (!(e instanceof Error))
                    return "";
                const r = e.stack || "";
                if (t.has(e))
                    return r + "\ncauses have become circular...";
                const o = n(e);
                return o ? (t.add(e),
                r + "\ncaused by: " + s(o, t)) : r
            }
            , o = (e, t, r) => {
                if (!(e instanceof Error))
                    return "";
                const s = r ? "" : e.message || "";
                if (t.has(e))
                    return s + ": ...";
                const i = n(e);
                if (i) {
                    t.add(e);
                    const r = "cause"in e && "function" == typeof e.cause;
                    return s + (r ? "" : ": ") + o(i, t, r)
                }
                return s
            }
        ;
        t.exports = {
            findCauseByReference: (e, t) => {
                if (!e || !t)
                    return;
                if (!(e instanceof Error))
                    return;
                if (!(t.prototype instanceof Error) && t !== Error)
                    return;
                const r = new Set;
                let s = e;
                for (; s && !r.has(s); ) {
                    if (r.add(s),
                    s instanceof t)
                        return s;
                    s = n(s)
                }
            }
            ,
            getErrorCause: n,
            stackWithCauses: e => s(e, new Set),
            messageWithCauses: e => o(e, new Set)
        }
    }
        , {}],
    211: [function(e, t, r) {
        var n, s, o = t.exports = {};
        function i() {
            throw new Error("setTimeout has not been defined")
        }
        function a() {
            throw new Error("clearTimeout has not been defined")
        }
        function c(e) {
            if (n === setTimeout)
                return setTimeout(e, 0);
            if ((n === i || !n) && setTimeout)
                return n = setTimeout,
                    setTimeout(e, 0);
            try {
                return n(e, 0)
            } catch (t) {
                try {
                    return n.call(null, e, 0)
                } catch (t) {
                    return n.call(this, e, 0)
                }
            }
        }
        !function() {
            try {
                n = "function" == typeof setTimeout ? setTimeout : i
            } catch (e) {
                n = i
            }
            try {
                s = "function" == typeof clearTimeout ? clearTimeout : a
            } catch (e) {
                s = a
            }
        }();
        var u, l = [], d = !1, f = -1;
        function p() {
            d && u && (d = !1,
                u.length ? l = u.concat(l) : f = -1,
            l.length && h())
        }
        function h() {
            if (!d) {
                var e = c(p);
                d = !0;
                for (var t = l.length; t; ) {
                    for (u = l,
                             l = []; ++f < t; )
                        u && u[f].run();
                    f = -1,
                        t = l.length
                }
                u = null,
                    d = !1,
                    function(e) {
                        if (s === clearTimeout)
                            return clearTimeout(e);
                        if ((s === a || !s) && clearTimeout)
                            return s = clearTimeout,
                                clearTimeout(e);
                        try {
                            return s(e)
                        } catch (t) {
                            try {
                                return s.call(null, e)
                            } catch (t) {
                                return s.call(this, e)
                            }
                        }
                    }(e)
            }
        }
        function g(e, t) {
            this.fun = e,
                this.array = t
        }
        function m() {}
        o.nextTick = function(e) {
            var t = new Array(arguments.length - 1);
            if (arguments.length > 1)
                for (var r = 1; r < arguments.length; r++)
                    t[r - 1] = arguments[r];
            l.push(new g(e,t)),
            1 !== l.length || d || c(h)
        }
            ,
            g.prototype.run = function() {
                this.fun.apply(null, this.array)
            }
            ,
            o.title = "browser",
            o.browser = !0,
            o.env = {},
            o.argv = [],
            o.version = "",
            o.versions = {},
            o.on = m,
            o.addListener = m,
            o.once = m,
            o.off = m,
            o.removeListener = m,
            o.removeAllListeners = m,
            o.emit = m,
            o.prependListener = m,
            o.prependOnceListener = m,
            o.listeners = function(e) {
                return []
            }
            ,
            o.binding = function(e) {
                throw new Error("process.binding is not supported")
            }
            ,
            o.cwd = function() {
                return "/"
            }
            ,
            o.chdir = function(e) {
                throw new Error("process.chdir is not supported")
            }
            ,
            o.umask = function() {
                return 0
            }
    }
        , {}],
    212: [function(e, t, r) {
        "use strict";
        var n = {};
        function s(e, t, r) {
            r || (r = Error);
            var s = function(e) {
                var r, n;
                function s(r, n, s) {
                    return e.call(this, function(e, r, n) {
                        return "string" == typeof t ? t : t(e, r, n)
                    }(r, n, s)) || this
                }
                return n = e,
                    (r = s).prototype = Object.create(n.prototype),
                    r.prototype.constructor = r,
                    r.__proto__ = n,
                    s
            }(r);
            s.prototype.name = r.name,
                s.prototype.code = e,
                n[e] = s
        }
        function o(e, t) {
            if (Array.isArray(e)) {
                var r = e.length;
                return e = e.map((function(e) {
                        return String(e)
                    }
                )),
                    r > 2 ? "one of ".concat(t, " ").concat(e.slice(0, r - 1).join(", "), ", or ") + e[r - 1] : 2 === r ? "one of ".concat(t, " ").concat(e[0], " or ").concat(e[1]) : "of ".concat(t, " ").concat(e[0])
            }
            return "of ".concat(t, " ").concat(String(e))
        }
        s("ERR_INVALID_OPT_VALUE", (function(e, t) {
                return 'The value "' + t + '" is invalid for option "' + e + '"'
            }
        ), TypeError),
            s("ERR_INVALID_ARG_TYPE", (function(e, t, r) {
                    var n, s, i, a;
                    if ("string" == typeof t && (s = "not ",
                    t.substr(!i || i < 0 ? 0 : +i, s.length) === s) ? (n = "must not be",
                        t = t.replace(/^not /, "")) : n = "must be",
                        function(e, t, r) {
                            return (void 0 === r || r > e.length) && (r = e.length),
                            e.substring(r - t.length, r) === t
                        }(e, " argument"))
                        a = "The ".concat(e, " ").concat(n, " ").concat(o(t, "type"));
                    else {
                        var c = function(e, t, r) {
                            return "number" != typeof r && (r = 0),
                            !(r + t.length > e.length) && -1 !== e.indexOf(t, r)
                        }(e, ".") ? "property" : "argument";
                        a = 'The "'.concat(e, '" ').concat(c, " ").concat(n, " ").concat(o(t, "type"))
                    }
                    return a += ". Received type ".concat(typeof r)
                }
            ), TypeError),
            s("ERR_STREAM_PUSH_AFTER_EOF", "stream.push() after EOF"),
            s("ERR_METHOD_NOT_IMPLEMENTED", (function(e) {
                    return "The " + e + " method is not implemented"
                }
            )),
            s("ERR_STREAM_PREMATURE_CLOSE", "Premature close"),
            s("ERR_STREAM_DESTROYED", (function(e) {
                    return "Cannot call " + e + " after a stream was destroyed"
                }
            )),
            s("ERR_MULTIPLE_CALLBACK", "Callback called multiple times"),
            s("ERR_STREAM_CANNOT_PIPE", "Cannot pipe, not readable"),
            s("ERR_STREAM_WRITE_AFTER_END", "write after end"),
            s("ERR_STREAM_NULL_VALUES", "May not write null values to stream", TypeError),
            s("ERR_UNKNOWN_ENCODING", (function(e) {
                    return "Unknown encoding: " + e
                }
            ), TypeError),
            s("ERR_STREAM_UNSHIFT_AFTER_END_EVENT", "stream.unshift() after end event"),
            t.exports.codes = n
    }
        , {}],
    213: [function(e, t, r) {
        (function(r) {
                (function() {
                        "use strict";
                        var n = Object.keys || function(e) {
                                var t = [];
                                for (var r in e)
                                    t.push(r);
                                return t
                            }
                        ;
                        t.exports = u;
                        var s = e("./_stream_readable")
                            , o = e("./_stream_writable");
                        e("inherits")(u, s);
                        for (var i = n(o.prototype), a = 0; a < i.length; a++) {
                            var c = i[a];
                            u.prototype[c] || (u.prototype[c] = o.prototype[c])
                        }
                        function u(e) {
                            if (!(this instanceof u))
                                return new u(e);
                            s.call(this, e),
                                o.call(this, e),
                                this.allowHalfOpen = !0,
                            e && (!1 === e.readable && (this.readable = !1),
                            !1 === e.writable && (this.writable = !1),
                            !1 === e.allowHalfOpen && (this.allowHalfOpen = !1,
                                this.once("end", l)))
                        }
                        function l() {
                            this._writableState.ended || r.nextTick(d, this)
                        }
                        function d(e) {
                            e.end()
                        }
                        Object.defineProperty(u.prototype, "writableHighWaterMark", {
                            enumerable: !1,
                            get: function() {
                                return this._writableState.highWaterMark
                            }
                        }),
                            Object.defineProperty(u.prototype, "writableBuffer", {
                                enumerable: !1,
                                get: function() {
                                    return this._writableState && this._writableState.getBuffer()
                                }
                            }),
                            Object.defineProperty(u.prototype, "writableLength", {
                                enumerable: !1,
                                get: function() {
                                    return this._writableState.length
                                }
                            }),
                            Object.defineProperty(u.prototype, "destroyed", {
                                enumerable: !1,
                                get: function() {
                                    return void 0 !== this._readableState && void 0 !== this._writableState && (this._readableState.destroyed && this._writableState.destroyed)
                                },
                                set: function(e) {
                                    void 0 !== this._readableState && void 0 !== this._writableState && (this._readableState.destroyed = e,
                                        this._writableState.destroyed = e)
                                }
                            })
                    }
                ).call(this)
            }
        ).call(this, e("_process"))
    }
        , {
            "./_stream_readable": 215,
            "./_stream_writable": 217,
            _process: 211,
            inherits: 204
        }],
    214: [function(e, t, r) {
        "use strict";
        t.exports = s;
        var n = e("./_stream_transform");
        function s(e) {
            if (!(this instanceof s))
                return new s(e);
            n.call(this, e)
        }
        e("inherits")(s, n),
            s.prototype._transform = function(e, t, r) {
                r(null, e)
            }
    }
        , {
            "./_stream_transform": 216,
            inherits: 204
        }],
    215: [function(e, t, r) {
        (function(r, n) {
                (function() {
                        "use strict";
                        var s;
                        t.exports = R,
                            R.ReadableState = j;
                        e("events").EventEmitter;
                        var o = function(e, t) {
                                return e.listeners(t).length
                            }
                            , i = e("./internal/streams/stream")
                            , a = e("buffer").Buffer
                            , c = (void 0 !== n ? n : "undefined" != typeof window ? window : "undefined" != typeof self ? self : {}).Uint8Array || function() {}
                        ;
                        var u, l = e("util");
                        u = l && l.debuglog ? l.debuglog("stream") : function() {}
                        ;
                        var d, f, p, h = e("./internal/streams/buffer_list"), g = e("./internal/streams/destroy"), m = e("./internal/streams/state").getHighWaterMark, b = e("../errors").codes, y = b.ERR_INVALID_ARG_TYPE, w = b.ERR_STREAM_PUSH_AFTER_EOF, v = b.ERR_METHOD_NOT_IMPLEMENTED, _ = b.ERR_STREAM_UNSHIFT_AFTER_END_EVENT;
                        e("inherits")(R, i);
                        var E = g.errorOrDestroy
                            , S = ["error", "close", "destroy", "pause", "resume"];
                        function j(t, r, n) {
                            s = s || e("./_stream_duplex"),
                                t = t || {},
                            "boolean" != typeof n && (n = r instanceof s),
                                this.objectMode = !!t.objectMode,
                            n && (this.objectMode = this.objectMode || !!t.readableObjectMode),
                                this.highWaterMark = m(this, t, "readableHighWaterMark", n),
                                this.buffer = new h,
                                this.length = 0,
                                this.pipes = null,
                                this.pipesCount = 0,
                                this.flowing = null,
                                this.ended = !1,
                                this.endEmitted = !1,
                                this.reading = !1,
                                this.sync = !0,
                                this.needReadable = !1,
                                this.emittedReadable = !1,
                                this.readableListening = !1,
                                this.resumeScheduled = !1,
                                this.paused = !0,
                                this.emitClose = !1 !== t.emitClose,
                                this.autoDestroy = !!t.autoDestroy,
                                this.destroyed = !1,
                                this.defaultEncoding = t.defaultEncoding || "utf8",
                                this.awaitDrain = 0,
                                this.readingMore = !1,
                                this.decoder = null,
                                this.encoding = null,
                            t.encoding && (d || (d = e("string_decoder/").StringDecoder),
                                this.decoder = new d(t.encoding),
                                this.encoding = t.encoding)
                        }
                        function R(t) {
                            if (s = s || e("./_stream_duplex"),
                                !(this instanceof R))
                                return new R(t);
                            var r = this instanceof s;
                            this._readableState = new j(t,this,r),
                                this.readable = !0,
                            t && ("function" == typeof t.read && (this._read = t.read),
                            "function" == typeof t.destroy && (this._destroy = t.destroy)),
                                i.call(this)
                        }
                        function I(e, t, r, n, s) {
                            u("readableAddChunk", t);
                            var o, i = e._readableState;
                            if (null === t)
                                i.reading = !1,
                                    function(e, t) {
                                        if (u("onEofChunk"),
                                            t.ended)
                                            return;
                                        if (t.decoder) {
                                            var r = t.decoder.end();
                                            r && r.length && (t.buffer.push(r),
                                                t.length += t.objectMode ? 1 : r.length)
                                        }
                                        t.ended = !0,
                                            t.sync ? C(e) : (t.needReadable = !1,
                                            t.emittedReadable || (t.emittedReadable = !0,
                                                O(e)))
                                    }(e, i);
                            else if (s || (o = function(e, t) {
                                var r;
                                n = t,
                                a.isBuffer(n) || n instanceof c || "string" == typeof t || void 0 === t || e.objectMode || (r = new y("chunk",["string", "Buffer", "Uint8Array"],t));
                                var n;
                                return r
                            }(i, t)),
                                o)
                                E(e, o);
                            else if (i.objectMode || t && t.length > 0)
                                if ("string" == typeof t || i.objectMode || Object.getPrototypeOf(t) === a.prototype || (t = function(e) {
                                    return a.from(e)
                                }(t)),
                                    n)
                                    i.endEmitted ? E(e, new _) : A(e, i, t, !0);
                                else if (i.ended)
                                    E(e, new w);
                                else {
                                    if (i.destroyed)
                                        return !1;
                                    i.reading = !1,
                                        i.decoder && !r ? (t = i.decoder.write(t),
                                            i.objectMode || 0 !== t.length ? A(e, i, t, !1) : x(e, i)) : A(e, i, t, !1)
                                }
                            else
                                n || (i.reading = !1,
                                    x(e, i));
                            return !i.ended && (i.length < i.highWaterMark || 0 === i.length)
                        }
                        function A(e, t, r, n) {
                            t.flowing && 0 === t.length && !t.sync ? (t.awaitDrain = 0,
                                e.emit("data", r)) : (t.length += t.objectMode ? 1 : r.length,
                                n ? t.buffer.unshift(r) : t.buffer.push(r),
                            t.needReadable && C(e)),
                                x(e, t)
                        }
                        Object.defineProperty(R.prototype, "destroyed", {
                            enumerable: !1,
                            get: function() {
                                return void 0 !== this._readableState && this._readableState.destroyed
                            },
                            set: function(e) {
                                this._readableState && (this._readableState.destroyed = e)
                            }
                        }),
                            R.prototype.destroy = g.destroy,
                            R.prototype._undestroy = g.undestroy,
                            R.prototype._destroy = function(e, t) {
                                t(e)
                            }
                            ,
                            R.prototype.push = function(e, t) {
                                var r, n = this._readableState;
                                return n.objectMode ? r = !0 : "string" == typeof e && ((t = t || n.defaultEncoding) !== n.encoding && (e = a.from(e, t),
                                    t = ""),
                                    r = !0),
                                    I(this, e, t, !1, r)
                            }
                            ,
                            R.prototype.unshift = function(e) {
                                return I(this, e, null, !0, !1)
                            }
                            ,
                            R.prototype.isPaused = function() {
                                return !1 === this._readableState.flowing
                            }
                            ,
                            R.prototype.setEncoding = function(t) {
                                d || (d = e("string_decoder/").StringDecoder);
                                var r = new d(t);
                                this._readableState.decoder = r,
                                    this._readableState.encoding = this._readableState.decoder.encoding;
                                for (var n = this._readableState.buffer.head, s = ""; null !== n; )
                                    s += r.write(n.data),
                                        n = n.next;
                                return this._readableState.buffer.clear(),
                                "" !== s && this._readableState.buffer.push(s),
                                    this._readableState.length = s.length,
                                    this
                            }
                        ;
                        var M = 1073741824;
                        function T(e, t) {
                            return e <= 0 || 0 === t.length && t.ended ? 0 : t.objectMode ? 1 : e != e ? t.flowing && t.length ? t.buffer.head.data.length : t.length : (e > t.highWaterMark && (t.highWaterMark = function(e) {
                                return e >= M ? e = M : (e--,
                                    e |= e >>> 1,
                                    e |= e >>> 2,
                                    e |= e >>> 4,
                                    e |= e >>> 8,
                                    e |= e >>> 16,
                                    e++),
                                    e
                            }(e)),
                                e <= t.length ? e : t.ended ? t.length : (t.needReadable = !0,
                                    0))
                        }
                        function C(e) {
                            var t = e._readableState;
                            u("emitReadable", t.needReadable, t.emittedReadable),
                                t.needReadable = !1,
                            t.emittedReadable || (u("emitReadable", t.flowing),
                                t.emittedReadable = !0,
                                r.nextTick(O, e))
                        }
                        function O(e) {
                            var t = e._readableState;
                            u("emitReadable_", t.destroyed, t.length, t.ended),
                            t.destroyed || !t.length && !t.ended || (e.emit("readable"),
                                t.emittedReadable = !1),
                                t.needReadable = !t.flowing && !t.ended && t.length <= t.highWaterMark,
                                D(e)
                        }
                        function x(e, t) {
                            t.readingMore || (t.readingMore = !0,
                                r.nextTick(N, e, t))
                        }
                        function N(e, t) {
                            for (; !t.reading && !t.ended && (t.length < t.highWaterMark || t.flowing && 0 === t.length); ) {
                                var r = t.length;
                                if (u("maybeReadMore read 0"),
                                    e.read(0),
                                r === t.length)
                                    break
                            }
                            t.readingMore = !1
                        }
                        function P(e) {
                            var t = e._readableState;
                            t.readableListening = e.listenerCount("readable") > 0,
                                t.resumeScheduled && !t.paused ? t.flowing = !0 : e.listenerCount("data") > 0 && e.resume()
                        }
                        function k(e) {
                            u("readable nexttick read 0"),
                                e.read(0)
                        }
                        function L(e, t) {
                            u("resume", t.reading),
                            t.reading || e.read(0),
                                t.resumeScheduled = !1,
                                e.emit("resume"),
                                D(e),
                            t.flowing && !t.reading && e.read(0)
                        }
                        function D(e) {
                            var t = e._readableState;
                            for (u("flow", t.flowing); t.flowing && null !== e.read(); )
                                ;
                        }
                        function B(e, t) {
                            return 0 === t.length ? null : (t.objectMode ? r = t.buffer.shift() : !e || e >= t.length ? (r = t.decoder ? t.buffer.join("") : 1 === t.buffer.length ? t.buffer.first() : t.buffer.concat(t.length),
                                t.buffer.clear()) : r = t.buffer.consume(e, t.decoder),
                                r);
                            var r
                        }
                        function $(e) {
                            var t = e._readableState;
                            u("endReadable", t.endEmitted),
                            t.endEmitted || (t.ended = !0,
                                r.nextTick(U, t, e))
                        }
                        function U(e, t) {
                            if (u("endReadableNT", e.endEmitted, e.length),
                            !e.endEmitted && 0 === e.length && (e.endEmitted = !0,
                                t.readable = !1,
                                t.emit("end"),
                                e.autoDestroy)) {
                                var r = t._writableState;
                                (!r || r.autoDestroy && r.finished) && t.destroy()
                            }
                        }
                        function F(e, t) {
                            for (var r = 0, n = e.length; r < n; r++)
                                if (e[r] === t)
                                    return r;
                            return -1
                        }
                        R.prototype.read = function(e) {
                            u("read", e),
                                e = parseInt(e, 10);
                            var t = this._readableState
                                , r = e;
                            if (0 !== e && (t.emittedReadable = !1),
                            0 === e && t.needReadable && ((0 !== t.highWaterMark ? t.length >= t.highWaterMark : t.length > 0) || t.ended))
                                return u("read: emitReadable", t.length, t.ended),
                                    0 === t.length && t.ended ? $(this) : C(this),
                                    null;
                            if (0 === (e = T(e, t)) && t.ended)
                                return 0 === t.length && $(this),
                                    null;
                            var n, s = t.needReadable;
                            return u("need readable", s),
                            (0 === t.length || t.length - e < t.highWaterMark) && u("length less than watermark", s = !0),
                                t.ended || t.reading ? u("reading or ended", s = !1) : s && (u("do read"),
                                    t.reading = !0,
                                    t.sync = !0,
                                0 === t.length && (t.needReadable = !0),
                                    this._read(t.highWaterMark),
                                    t.sync = !1,
                                t.reading || (e = T(r, t))),
                                null === (n = e > 0 ? B(e, t) : null) ? (t.needReadable = t.length <= t.highWaterMark,
                                    e = 0) : (t.length -= e,
                                    t.awaitDrain = 0),
                            0 === t.length && (t.ended || (t.needReadable = !0),
                            r !== e && t.ended && $(this)),
                            null !== n && this.emit("data", n),
                                n
                        }
                            ,
                            R.prototype._read = function(e) {
                                E(this, new v("_read()"))
                            }
                            ,
                            R.prototype.pipe = function(e, t) {
                                var n = this
                                    , s = this._readableState;
                                switch (s.pipesCount) {
                                    case 0:
                                        s.pipes = e;
                                        break;
                                    case 1:
                                        s.pipes = [s.pipes, e];
                                        break;
                                    default:
                                        s.pipes.push(e)
                                }
                                s.pipesCount += 1,
                                    u("pipe count=%d opts=%j", s.pipesCount, t);
                                var i = (!t || !1 !== t.end) && e !== r.stdout && e !== r.stderr ? c : m;
                                function a(t, r) {
                                    u("onunpipe"),
                                    t === n && r && !1 === r.hasUnpiped && (r.hasUnpiped = !0,
                                        u("cleanup"),
                                        e.removeListener("close", h),
                                        e.removeListener("finish", g),
                                        e.removeListener("drain", l),
                                        e.removeListener("error", p),
                                        e.removeListener("unpipe", a),
                                        n.removeListener("end", c),
                                        n.removeListener("end", m),
                                        n.removeListener("data", f),
                                        d = !0,
                                    !s.awaitDrain || e._writableState && !e._writableState.needDrain || l())
                                }
                                function c() {
                                    u("onend"),
                                        e.end()
                                }
                                s.endEmitted ? r.nextTick(i) : n.once("end", i),
                                    e.on("unpipe", a);
                                var l = function(e) {
                                    return function() {
                                        var t = e._readableState;
                                        u("pipeOnDrain", t.awaitDrain),
                                        t.awaitDrain && t.awaitDrain--,
                                        0 === t.awaitDrain && o(e, "data") && (t.flowing = !0,
                                            D(e))
                                    }
                                }(n);
                                e.on("drain", l);
                                var d = !1;
                                function f(t) {
                                    u("ondata");
                                    var r = e.write(t);
                                    u("dest.write", r),
                                    !1 === r && ((1 === s.pipesCount && s.pipes === e || s.pipesCount > 1 && -1 !== F(s.pipes, e)) && !d && (u("false write response, pause", s.awaitDrain),
                                        s.awaitDrain++),
                                        n.pause())
                                }
                                function p(t) {
                                    u("onerror", t),
                                        m(),
                                        e.removeListener("error", p),
                                    0 === o(e, "error") && E(e, t)
                                }
                                function h() {
                                    e.removeListener("finish", g),
                                        m()
                                }
                                function g() {
                                    u("onfinish"),
                                        e.removeListener("close", h),
                                        m()
                                }
                                function m() {
                                    u("unpipe"),
                                        n.unpipe(e)
                                }
                                return n.on("data", f),
                                    function(e, t, r) {
                                        if ("function" == typeof e.prependListener)
                                            return e.prependListener(t, r);
                                        e._events && e._events[t] ? Array.isArray(e._events[t]) ? e._events[t].unshift(r) : e._events[t] = [r, e._events[t]] : e.on(t, r)
                                    }(e, "error", p),
                                    e.once("close", h),
                                    e.once("finish", g),
                                    e.emit("pipe", n),
                                s.flowing || (u("pipe resume"),
                                    n.resume()),
                                    e
                            }
                            ,
                            R.prototype.unpipe = function(e) {
                                var t = this._readableState
                                    , r = {
                                    hasUnpiped: !1
                                };
                                if (0 === t.pipesCount)
                                    return this;
                                if (1 === t.pipesCount)
                                    return e && e !== t.pipes || (e || (e = t.pipes),
                                        t.pipes = null,
                                        t.pipesCount = 0,
                                        t.flowing = !1,
                                    e && e.emit("unpipe", this, r)),
                                        this;
                                if (!e) {
                                    var n = t.pipes
                                        , s = t.pipesCount;
                                    t.pipes = null,
                                        t.pipesCount = 0,
                                        t.flowing = !1;
                                    for (var o = 0; o < s; o++)
                                        n[o].emit("unpipe", this, {
                                            hasUnpiped: !1
                                        });
                                    return this
                                }
                                var i = F(t.pipes, e);
                                return -1 === i || (t.pipes.splice(i, 1),
                                    t.pipesCount -= 1,
                                1 === t.pipesCount && (t.pipes = t.pipes[0]),
                                    e.emit("unpipe", this, r)),
                                    this
                            }
                            ,
                            R.prototype.on = function(e, t) {
                                var n = i.prototype.on.call(this, e, t)
                                    , s = this._readableState;
                                return "data" === e ? (s.readableListening = this.listenerCount("readable") > 0,
                                !1 !== s.flowing && this.resume()) : "readable" === e && (s.endEmitted || s.readableListening || (s.readableListening = s.needReadable = !0,
                                    s.flowing = !1,
                                    s.emittedReadable = !1,
                                    u("on readable", s.length, s.reading),
                                    s.length ? C(this) : s.reading || r.nextTick(k, this))),
                                    n
                            }
                            ,
                            R.prototype.addListener = R.prototype.on,
                            R.prototype.removeListener = function(e, t) {
                                var n = i.prototype.removeListener.call(this, e, t);
                                return "readable" === e && r.nextTick(P, this),
                                    n
                            }
                            ,
                            R.prototype.removeAllListeners = function(e) {
                                var t = i.prototype.removeAllListeners.apply(this, arguments);
                                return "readable" !== e && void 0 !== e || r.nextTick(P, this),
                                    t
                            }
                            ,
                            R.prototype.resume = function() {
                                var e = this._readableState;
                                return e.flowing || (u("resume"),
                                    e.flowing = !e.readableListening,
                                    function(e, t) {
                                        t.resumeScheduled || (t.resumeScheduled = !0,
                                            r.nextTick(L, e, t))
                                    }(this, e)),
                                    e.paused = !1,
                                    this
                            }
                            ,
                            R.prototype.pause = function() {
                                return u("call pause flowing=%j", this._readableState.flowing),
                                !1 !== this._readableState.flowing && (u("pause"),
                                    this._readableState.flowing = !1,
                                    this.emit("pause")),
                                    this._readableState.paused = !0,
                                    this
                            }
                            ,
                            R.prototype.wrap = function(e) {
                                var t = this
                                    , r = this._readableState
                                    , n = !1;
                                for (var s in e.on("end", (function() {
                                        if (u("wrapped end"),
                                        r.decoder && !r.ended) {
                                            var e = r.decoder.end();
                                            e && e.length && t.push(e)
                                        }
                                        t.push(null)
                                    }
                                )),
                                    e.on("data", (function(s) {
                                            (u("wrapped data"),
                                            r.decoder && (s = r.decoder.write(s)),
                                            r.objectMode && null == s) || (r.objectMode || s && s.length) && (t.push(s) || (n = !0,
                                                e.pause()))
                                        }
                                    )),
                                    e)
                                    void 0 === this[s] && "function" == typeof e[s] && (this[s] = function(t) {
                                        return function() {
                                            return e[t].apply(e, arguments)
                                        }
                                    }(s));
                                for (var o = 0; o < S.length; o++)
                                    e.on(S[o], this.emit.bind(this, S[o]));
                                return this._read = function(t) {
                                    u("wrapped _read", t),
                                    n && (n = !1,
                                        e.resume())
                                }
                                    ,
                                    this
                            }
                            ,
                        "function" == typeof Symbol && (R.prototype[Symbol.asyncIterator] = function() {
                                return void 0 === f && (f = e("./internal/streams/async_iterator")),
                                    f(this)
                            }
                        ),
                            Object.defineProperty(R.prototype, "readableHighWaterMark", {
                                enumerable: !1,
                                get: function() {
                                    return this._readableState.highWaterMark
                                }
                            }),
                            Object.defineProperty(R.prototype, "readableBuffer", {
                                enumerable: !1,
                                get: function() {
                                    return this._readableState && this._readableState.buffer
                                }
                            }),
                            Object.defineProperty(R.prototype, "readableFlowing", {
                                enumerable: !1,
                                get: function() {
                                    return this._readableState.flowing
                                },
                                set: function(e) {
                                    this._readableState && (this._readableState.flowing = e)
                                }
                            }),
                            R._fromList = B,
                            Object.defineProperty(R.prototype, "readableLength", {
                                enumerable: !1,
                                get: function() {
                                    return this._readableState.length
                                }
                            }),
                        "function" == typeof Symbol && (R.from = function(t, r) {
                                return void 0 === p && (p = e("./internal/streams/from")),
                                    p(R, t, r)
                            }
                        )
                    }
                ).call(this)
            }
        ).call(this, e("_process"), "undefined" != typeof global ? global : "undefined" != typeof self ? self : "undefined" != typeof window ? window : {})
    }
        , {
            "../errors": 212,
            "./_stream_duplex": 213,
            "./internal/streams/async_iterator": 218,
            "./internal/streams/buffer_list": 219,
            "./internal/streams/destroy": 220,
            "./internal/streams/from": 222,
            "./internal/streams/state": 224,
            "./internal/streams/stream": 225,
            _process: 211,
            buffer: 195,
            events: 200,
            inherits: 204,
            "string_decoder/": 273,
            util: 194
        }],
    216: [function(e, t, r) {
        "use strict";
        t.exports = l;
        var n = e("../errors").codes
            , s = n.ERR_METHOD_NOT_IMPLEMENTED
            , o = n.ERR_MULTIPLE_CALLBACK
            , i = n.ERR_TRANSFORM_ALREADY_TRANSFORMING
            , a = n.ERR_TRANSFORM_WITH_LENGTH_0
            , c = e("./_stream_duplex");
        function u(e, t) {
            var r = this._transformState;
            r.transforming = !1;
            var n = r.writecb;
            if (null === n)
                return this.emit("error", new o);
            r.writechunk = null,
                r.writecb = null,
            null != t && this.push(t),
                n(e);
            var s = this._readableState;
            s.reading = !1,
            (s.needReadable || s.length < s.highWaterMark) && this._read(s.highWaterMark)
        }
        function l(e) {
            if (!(this instanceof l))
                return new l(e);
            c.call(this, e),
                this._transformState = {
                    afterTransform: u.bind(this),
                    needTransform: !1,
                    transforming: !1,
                    writecb: null,
                    writechunk: null,
                    writeencoding: null
                },
                this._readableState.needReadable = !0,
                this._readableState.sync = !1,
            e && ("function" == typeof e.transform && (this._transform = e.transform),
            "function" == typeof e.flush && (this._flush = e.flush)),
                this.on("prefinish", d)
        }
        function d() {
            var e = this;
            "function" != typeof this._flush || this._readableState.destroyed ? f(this, null, null) : this._flush((function(t, r) {
                    f(e, t, r)
                }
            ))
        }
        function f(e, t, r) {
            if (t)
                return e.emit("error", t);
            if (null != r && e.push(r),
                e._writableState.length)
                throw new a;
            if (e._transformState.transforming)
                throw new i;
            return e.push(null)
        }
        e("inherits")(l, c),
            l.prototype.push = function(e, t) {
                return this._transformState.needTransform = !1,
                    c.prototype.push.call(this, e, t)
            }
            ,
            l.prototype._transform = function(e, t, r) {
                r(new s("_transform()"))
            }
            ,
            l.prototype._write = function(e, t, r) {
                var n = this._transformState;
                if (n.writecb = r,
                    n.writechunk = e,
                    n.writeencoding = t,
                    !n.transforming) {
                    var s = this._readableState;
                    (n.needTransform || s.needReadable || s.length < s.highWaterMark) && this._read(s.highWaterMark)
                }
            }
            ,
            l.prototype._read = function(e) {
                var t = this._transformState;
                null === t.writechunk || t.transforming ? t.needTransform = !0 : (t.transforming = !0,
                    this._transform(t.writechunk, t.writeencoding, t.afterTransform))
            }
            ,
            l.prototype._destroy = function(e, t) {
                c.prototype._destroy.call(this, e, (function(e) {
                        t(e)
                    }
                ))
            }
    }
        , {
            "../errors": 212,
            "./_stream_duplex": 213,
            inherits: 204
        }],
    217: [function(e, t, r) {
        (function(r, n) {
                (function() {
                        "use strict";
                        function s(e) {
                            var t = this;
                            this.next = null,
                                this.entry = null,
                                this.finish = function() {
                                    !function(e, t, r) {
                                        var n = e.entry;
                                        e.entry = null;
                                        for (; n; ) {
                                            var s = n.callback;
                                            t.pendingcb--,
                                                s(r),
                                                n = n.next
                                        }
                                        t.corkedRequestsFree.next = e
                                    }(t, e)
                                }
                        }
                        var o;
                        t.exports = R,
                            R.WritableState = j;
                        var i = {
                                deprecate: e("util-deprecate")
                            }
                            , a = e("./internal/streams/stream")
                            , c = e("buffer").Buffer
                            , u = (void 0 !== n ? n : "undefined" != typeof window ? window : "undefined" != typeof self ? self : {}).Uint8Array || function() {}
                        ;
                        var l, d = e("./internal/streams/destroy"), f = e("./internal/streams/state").getHighWaterMark, p = e("../errors").codes, h = p.ERR_INVALID_ARG_TYPE, g = p.ERR_METHOD_NOT_IMPLEMENTED, m = p.ERR_MULTIPLE_CALLBACK, b = p.ERR_STREAM_CANNOT_PIPE, y = p.ERR_STREAM_DESTROYED, w = p.ERR_STREAM_NULL_VALUES, v = p.ERR_STREAM_WRITE_AFTER_END, _ = p.ERR_UNKNOWN_ENCODING, E = d.errorOrDestroy;
                        function S() {}
                        function j(t, n, i) {
                            o = o || e("./_stream_duplex"),
                                t = t || {},
                            "boolean" != typeof i && (i = n instanceof o),
                                this.objectMode = !!t.objectMode,
                            i && (this.objectMode = this.objectMode || !!t.writableObjectMode),
                                this.highWaterMark = f(this, t, "writableHighWaterMark", i),
                                this.finalCalled = !1,
                                this.needDrain = !1,
                                this.ending = !1,
                                this.ended = !1,
                                this.finished = !1,
                                this.destroyed = !1;
                            var a = !1 === t.decodeStrings;
                            this.decodeStrings = !a,
                                this.defaultEncoding = t.defaultEncoding || "utf8",
                                this.length = 0,
                                this.writing = !1,
                                this.corked = 0,
                                this.sync = !0,
                                this.bufferProcessing = !1,
                                this.onwrite = function(e) {
                                    !function(e, t) {
                                        var n = e._writableState
                                            , s = n.sync
                                            , o = n.writecb;
                                        if ("function" != typeof o)
                                            throw new m;
                                        if (function(e) {
                                            e.writing = !1,
                                                e.writecb = null,
                                                e.length -= e.writelen,
                                                e.writelen = 0
                                        }(n),
                                            t)
                                            !function(e, t, n, s, o) {
                                                --t.pendingcb,
                                                    n ? (r.nextTick(o, s),
                                                        r.nextTick(O, e, t),
                                                        e._writableState.errorEmitted = !0,
                                                        E(e, s)) : (o(s),
                                                        e._writableState.errorEmitted = !0,
                                                        E(e, s),
                                                        O(e, t))
                                            }(e, n, s, t, o);
                                        else {
                                            var i = T(n) || e.destroyed;
                                            i || n.corked || n.bufferProcessing || !n.bufferedRequest || M(e, n),
                                                s ? r.nextTick(A, e, n, i, o) : A(e, n, i, o)
                                        }
                                    }(n, e)
                                }
                                ,
                                this.writecb = null,
                                this.writelen = 0,
                                this.bufferedRequest = null,
                                this.lastBufferedRequest = null,
                                this.pendingcb = 0,
                                this.prefinished = !1,
                                this.errorEmitted = !1,
                                this.emitClose = !1 !== t.emitClose,
                                this.autoDestroy = !!t.autoDestroy,
                                this.bufferedRequestCount = 0,
                                this.corkedRequestsFree = new s(this)
                        }
                        function R(t) {
                            var r = this instanceof (o = o || e("./_stream_duplex"));
                            if (!r && !l.call(R, this))
                                return new R(t);
                            this._writableState = new j(t,this,r),
                                this.writable = !0,
                            t && ("function" == typeof t.write && (this._write = t.write),
                            "function" == typeof t.writev && (this._writev = t.writev),
                            "function" == typeof t.destroy && (this._destroy = t.destroy),
                            "function" == typeof t.final && (this._final = t.final)),
                                a.call(this)
                        }
                        function I(e, t, r, n, s, o, i) {
                            t.writelen = n,
                                t.writecb = i,
                                t.writing = !0,
                                t.sync = !0,
                                t.destroyed ? t.onwrite(new y("write")) : r ? e._writev(s, t.onwrite) : e._write(s, o, t.onwrite),
                                t.sync = !1
                        }
                        function A(e, t, r, n) {
                            r || function(e, t) {
                                0 === t.length && t.needDrain && (t.needDrain = !1,
                                    e.emit("drain"))
                            }(e, t),
                                t.pendingcb--,
                                n(),
                                O(e, t)
                        }
                        function M(e, t) {
                            t.bufferProcessing = !0;
                            var r = t.bufferedRequest;
                            if (e._writev && r && r.next) {
                                var n = t.bufferedRequestCount
                                    , o = new Array(n)
                                    , i = t.corkedRequestsFree;
                                i.entry = r;
                                for (var a = 0, c = !0; r; )
                                    o[a] = r,
                                    r.isBuf || (c = !1),
                                        r = r.next,
                                        a += 1;
                                o.allBuffers = c,
                                    I(e, t, !0, t.length, o, "", i.finish),
                                    t.pendingcb++,
                                    t.lastBufferedRequest = null,
                                    i.next ? (t.corkedRequestsFree = i.next,
                                        i.next = null) : t.corkedRequestsFree = new s(t),
                                    t.bufferedRequestCount = 0
                            } else {
                                for (; r; ) {
                                    var u = r.chunk
                                        , l = r.encoding
                                        , d = r.callback;
                                    if (I(e, t, !1, t.objectMode ? 1 : u.length, u, l, d),
                                        r = r.next,
                                        t.bufferedRequestCount--,
                                        t.writing)
                                        break
                                }
                                null === r && (t.lastBufferedRequest = null)
                            }
                            t.bufferedRequest = r,
                                t.bufferProcessing = !1
                        }
                        function T(e) {
                            return e.ending && 0 === e.length && null === e.bufferedRequest && !e.finished && !e.writing
                        }
                        function C(e, t) {
                            e._final((function(r) {
                                    t.pendingcb--,
                                    r && E(e, r),
                                        t.prefinished = !0,
                                        e.emit("prefinish"),
                                        O(e, t)
                                }
                            ))
                        }
                        function O(e, t) {
                            var n = T(t);
                            if (n && (function(e, t) {
                                t.prefinished || t.finalCalled || ("function" != typeof e._final || t.destroyed ? (t.prefinished = !0,
                                    e.emit("prefinish")) : (t.pendingcb++,
                                    t.finalCalled = !0,
                                    r.nextTick(C, e, t)))
                            }(e, t),
                            0 === t.pendingcb && (t.finished = !0,
                                e.emit("finish"),
                                t.autoDestroy))) {
                                var s = e._readableState;
                                (!s || s.autoDestroy && s.endEmitted) && e.destroy()
                            }
                            return n
                        }
                        e("inherits")(R, a),
                            j.prototype.getBuffer = function() {
                                for (var e = this.bufferedRequest, t = []; e; )
                                    t.push(e),
                                        e = e.next;
                                return t
                            }
                            ,
                            function() {
                                try {
                                    Object.defineProperty(j.prototype, "buffer", {
                                        get: i.deprecate((function() {
                                                return this.getBuffer()
                                            }
                                        ), "_writableState.buffer is deprecated. Use _writableState.getBuffer instead.", "DEP0003")
                                    })
                                } catch (e) {}
                            }(),
                            "function" == typeof Symbol && Symbol.hasInstance && "function" == typeof Function.prototype[Symbol.hasInstance] ? (l = Function.prototype[Symbol.hasInstance],
                                Object.defineProperty(R, Symbol.hasInstance, {
                                    value: function(e) {
                                        return !!l.call(this, e) || this === R && (e && e._writableState instanceof j)
                                    }
                                })) : l = function(e) {
                                return e instanceof this
                            }
                            ,
                            R.prototype.pipe = function() {
                                E(this, new b)
                            }
                            ,
                            R.prototype.write = function(e, t, n) {
                                var s, o = this._writableState, i = !1, a = !o.objectMode && (s = e,
                                c.isBuffer(s) || s instanceof u);
                                return a && !c.isBuffer(e) && (e = function(e) {
                                    return c.from(e)
                                }(e)),
                                "function" == typeof t && (n = t,
                                    t = null),
                                    a ? t = "buffer" : t || (t = o.defaultEncoding),
                                "function" != typeof n && (n = S),
                                    o.ending ? function(e, t) {
                                        var n = new v;
                                        E(e, n),
                                            r.nextTick(t, n)
                                    }(this, n) : (a || function(e, t, n, s) {
                                        var o;
                                        return null === n ? o = new w : "string" == typeof n || t.objectMode || (o = new h("chunk",["string", "Buffer"],n)),
                                        !o || (E(e, o),
                                            r.nextTick(s, o),
                                            !1)
                                    }(this, o, e, n)) && (o.pendingcb++,
                                        i = function(e, t, r, n, s, o) {
                                            if (!r) {
                                                var i = function(e, t, r) {
                                                    e.objectMode || !1 === e.decodeStrings || "string" != typeof t || (t = c.from(t, r));
                                                    return t
                                                }(t, n, s);
                                                n !== i && (r = !0,
                                                    s = "buffer",
                                                    n = i)
                                            }
                                            var a = t.objectMode ? 1 : n.length;
                                            t.length += a;
                                            var u = t.length < t.highWaterMark;
                                            u || (t.needDrain = !0);
                                            if (t.writing || t.corked) {
                                                var l = t.lastBufferedRequest;
                                                t.lastBufferedRequest = {
                                                    chunk: n,
                                                    encoding: s,
                                                    isBuf: r,
                                                    callback: o,
                                                    next: null
                                                },
                                                    l ? l.next = t.lastBufferedRequest : t.bufferedRequest = t.lastBufferedRequest,
                                                    t.bufferedRequestCount += 1
                                            } else
                                                I(e, t, !1, a, n, s, o);
                                            return u
                                        }(this, o, a, e, t, n)),
                                    i
                            }
                            ,
                            R.prototype.cork = function() {
                                this._writableState.corked++
                            }
                            ,
                            R.prototype.uncork = function() {
                                var e = this._writableState;
                                e.corked && (e.corked--,
                                e.writing || e.corked || e.bufferProcessing || !e.bufferedRequest || M(this, e))
                            }
                            ,
                            R.prototype.setDefaultEncoding = function(e) {
                                if ("string" == typeof e && (e = e.toLowerCase()),
                                    !(["hex", "utf8", "utf-8", "ascii", "binary", "base64", "ucs2", "ucs-2", "utf16le", "utf-16le", "raw"].indexOf((e + "").toLowerCase()) > -1))
                                    throw new _(e);
                                return this._writableState.defaultEncoding = e,
                                    this
                            }
                            ,
                            Object.defineProperty(R.prototype, "writableBuffer", {
                                enumerable: !1,
                                get: function() {
                                    return this._writableState && this._writableState.getBuffer()
                                }
                            }),
                            Object.defineProperty(R.prototype, "writableHighWaterMark", {
                                enumerable: !1,
                                get: function() {
                                    return this._writableState.highWaterMark
                                }
                            }),
                            R.prototype._write = function(e, t, r) {
                                r(new g("_write()"))
                            }
                            ,
                            R.prototype._writev = null,
                            R.prototype.end = function(e, t, n) {
                                var s = this._writableState;
                                return "function" == typeof e ? (n = e,
                                    e = null,
                                    t = null) : "function" == typeof t && (n = t,
                                    t = null),
                                null != e && this.write(e, t),
                                s.corked && (s.corked = 1,
                                    this.uncork()),
                                s.ending || function(e, t, n) {
                                    t.ending = !0,
                                        O(e, t),
                                    n && (t.finished ? r.nextTick(n) : e.once("finish", n));
                                    t.ended = !0,
                                        e.writable = !1
                                }(this, s, n),
                                    this
                            }
                            ,
                            Object.defineProperty(R.prototype, "writableLength", {
                                enumerable: !1,
                                get: function() {
                                    return this._writableState.length
                                }
                            }),
                            Object.defineProperty(R.prototype, "destroyed", {
                                enumerable: !1,
                                get: function() {
                                    return void 0 !== this._writableState && this._writableState.destroyed
                                },
                                set: function(e) {
                                    this._writableState && (this._writableState.destroyed = e)
                                }
                            }),
                            R.prototype.destroy = d.destroy,
                            R.prototype._undestroy = d.undestroy,
                            R.prototype._destroy = function(e, t) {
                                t(e)
                            }
                    }
                ).call(this)
            }
        ).call(this, e("_process"), "undefined" != typeof global ? global : "undefined" != typeof self ? self : "undefined" != typeof window ? window : {})
    }
        , {
            "../errors": 212,
            "./_stream_duplex": 213,
            "./internal/streams/destroy": 220,
            "./internal/streams/state": 224,
            "./internal/streams/stream": 225,
            _process: 211,
            buffer: 195,
            inherits: 204,
            "util-deprecate": 274
        }],
    218: [function(e, t, r) {
        (function(r) {
                (function() {
                        "use strict";
                        var n;
                        function s(e, t, r) {
                            return (t = function(e) {
                                var t = function(e, t) {
                                    if ("object" != typeof e || null === e)
                                        return e;
                                    var r = e[Symbol.toPrimitive];
                                    if (void 0 !== r) {
                                        var n = r.call(e, t || "default");
                                        if ("object" != typeof n)
                                            return n;
                                        throw new TypeError("@@toPrimitive must return a primitive value.")
                                    }
                                    return ("string" === t ? String : Number)(e)
                                }(e, "string");
                                return "symbol" == typeof t ? t : String(t)
                            }(t))in e ? Object.defineProperty(e, t, {
                                value: r,
                                enumerable: !0,
                                configurable: !0,
                                writable: !0
                            }) : e[t] = r,
                                e
                        }
                        var o = e("./end-of-stream")
                            , i = Symbol("lastResolve")
                            , a = Symbol("lastReject")
                            , c = Symbol("error")
                            , u = Symbol("ended")
                            , l = Symbol("lastPromise")
                            , d = Symbol("handlePromise")
                            , f = Symbol("stream");
                        function p(e, t) {
                            return {
                                value: e,
                                done: t
                            }
                        }
                        function h(e) {
                            var t = e[i];
                            if (null !== t) {
                                var r = e[f].read();
                                null !== r && (e[l] = null,
                                    e[i] = null,
                                    e[a] = null,
                                    t(p(r, !1)))
                            }
                        }
                        function g(e) {
                            r.nextTick(h, e)
                        }
                        var m = Object.getPrototypeOf((function() {}
                        ))
                            , b = Object.setPrototypeOf((s(n = {
                            get stream() {
                                return this[f]
                            },
                            next: function() {
                                var e = this
                                    , t = this[c];
                                if (null !== t)
                                    return Promise.reject(t);
                                if (this[u])
                                    return Promise.resolve(p(void 0, !0));
                                if (this[f].destroyed)
                                    return new Promise((function(t, n) {
                                            r.nextTick((function() {
                                                    e[c] ? n(e[c]) : t(p(void 0, !0))
                                                }
                                            ))
                                        }
                                    ));
                                var n, s = this[l];
                                if (s)
                                    n = new Promise(function(e, t) {
                                        return function(r, n) {
                                            e.then((function() {
                                                    t[u] ? r(p(void 0, !0)) : t[d](r, n)
                                                }
                                            ), n)
                                        }
                                    }(s, this));
                                else {
                                    var o = this[f].read();
                                    if (null !== o)
                                        return Promise.resolve(p(o, !1));
                                    n = new Promise(this[d])
                                }
                                return this[l] = n,
                                    n
                            }
                        }, Symbol.asyncIterator, (function() {
                                return this
                            }
                        )),
                            s(n, "return", (function() {
                                    var e = this;
                                    return new Promise((function(t, r) {
                                            e[f].destroy(null, (function(e) {
                                                    e ? r(e) : t(p(void 0, !0))
                                                }
                                            ))
                                        }
                                    ))
                                }
                            )),
                            n), m);
                        t.exports = function(e) {
                            var t, r = Object.create(b, (s(t = {}, f, {
                                value: e,
                                writable: !0
                            }),
                                s(t, i, {
                                    value: null,
                                    writable: !0
                                }),
                                s(t, a, {
                                    value: null,
                                    writable: !0
                                }),
                                s(t, c, {
                                    value: null,
                                    writable: !0
                                }),
                                s(t, u, {
                                    value: e._readableState.endEmitted,
                                    writable: !0
                                }),
                                s(t, d, {
                                    value: function(e, t) {
                                        var n = r[f].read();
                                        n ? (r[l] = null,
                                            r[i] = null,
                                            r[a] = null,
                                            e(p(n, !1))) : (r[i] = e,
                                            r[a] = t)
                                    },
                                    writable: !0
                                }),
                                t));
                            return r[l] = null,
                                o(e, (function(e) {
                                        if (e && "ERR_STREAM_PREMATURE_CLOSE" !== e.code) {
                                            var t = r[a];
                                            return null !== t && (r[l] = null,
                                                r[i] = null,
                                                r[a] = null,
                                                t(e)),
                                                void (r[c] = e)
                                        }
                                        var n = r[i];
                                        null !== n && (r[l] = null,
                                            r[i] = null,
                                            r[a] = null,
                                            n(p(void 0, !0))),
                                            r[u] = !0
                                    }
                                )),
                                e.on("readable", g.bind(null, r)),
                                r
                        }
                    }
                ).call(this)
            }
        ).call(this, e("_process"))
    }
        , {
            "./end-of-stream": 221,
            _process: 211
        }],
    219: [function(e, t, r) {
        "use strict";
        function n(e, t) {
            var r = Object.keys(e);
            if (Object.getOwnPropertySymbols) {
                var n = Object.getOwnPropertySymbols(e);
                t && (n = n.filter((function(t) {
                        return Object.getOwnPropertyDescriptor(e, t).enumerable
                    }
                ))),
                    r.push.apply(r, n)
            }
            return r
        }
        function s(e) {
            for (var t = 1; t < arguments.length; t++) {
                var r = null != arguments[t] ? arguments[t] : {};
                t % 2 ? n(Object(r), !0).forEach((function(t) {
                        o(e, t, r[t])
                    }
                )) : Object.getOwnPropertyDescriptors ? Object.defineProperties(e, Object.getOwnPropertyDescriptors(r)) : n(Object(r)).forEach((function(t) {
                        Object.defineProperty(e, t, Object.getOwnPropertyDescriptor(r, t))
                    }
                ))
            }
            return e
        }
        function o(e, t, r) {
            return (t = a(t))in e ? Object.defineProperty(e, t, {
                value: r,
                enumerable: !0,
                configurable: !0,
                writable: !0
            }) : e[t] = r,
                e
        }
        function i(e, t) {
            for (var r = 0; r < t.length; r++) {
                var n = t[r];
                n.enumerable = n.enumerable || !1,
                    n.configurable = !0,
                "value"in n && (n.writable = !0),
                    Object.defineProperty(e, a(n.key), n)
            }
        }
        function a(e) {
            var t = function(e, t) {
                if ("object" != typeof e || null === e)
                    return e;
                var r = e[Symbol.toPrimitive];
                if (void 0 !== r) {
                    var n = r.call(e, t || "default");
                    if ("object" != typeof n)
                        return n;
                    throw new TypeError("@@toPrimitive must return a primitive value.")
                }
                return ("string" === t ? String : Number)(e)
            }(e, "string");
            return "symbol" == typeof t ? t : String(t)
        }
        var c = e("buffer").Buffer
            , u = e("util").inspect
            , l = u && u.custom || "inspect";
        t.exports = function() {
            function e() {
                !function(e, t) {
                    if (!(e instanceof t))
                        throw new TypeError("Cannot call a class as a function")
                }(this, e),
                    this.head = null,
                    this.tail = null,
                    this.length = 0
            }
            var t, r, n;
            return t = e,
            (r = [{
                key: "push",
                value: function(e) {
                    var t = {
                        data: e,
                        next: null
                    };
                    this.length > 0 ? this.tail.next = t : this.head = t,
                        this.tail = t,
                        ++this.length
                }
            }, {
                key: "unshift",
                value: function(e) {
                    var t = {
                        data: e,
                        next: this.head
                    };
                    0 === this.length && (this.tail = t),
                        this.head = t,
                        ++this.length
                }
            }, {
                key: "shift",
                value: function() {
                    if (0 !== this.length) {
                        var e = this.head.data;
                        return 1 === this.length ? this.head = this.tail = null : this.head = this.head.next,
                            --this.length,
                            e
                    }
                }
            }, {
                key: "clear",
                value: function() {
                    this.head = this.tail = null,
                        this.length = 0
                }
            }, {
                key: "join",
                value: function(e) {
                    if (0 === this.length)
                        return "";
                    for (var t = this.head, r = "" + t.data; t = t.next; )
                        r += e + t.data;
                    return r
                }
            }, {
                key: "concat",
                value: function(e) {
                    if (0 === this.length)
                        return c.alloc(0);
                    for (var t, r, n, s = c.allocUnsafe(e >>> 0), o = this.head, i = 0; o; )
                        t = o.data,
                            r = s,
                            n = i,
                            c.prototype.copy.call(t, r, n),
                            i += o.data.length,
                            o = o.next;
                    return s
                }
            }, {
                key: "consume",
                value: function(e, t) {
                    var r;
                    return e < this.head.data.length ? (r = this.head.data.slice(0, e),
                        this.head.data = this.head.data.slice(e)) : r = e === this.head.data.length ? this.shift() : t ? this._getString(e) : this._getBuffer(e),
                        r
                }
            }, {
                key: "first",
                value: function() {
                    return this.head.data
                }
            }, {
                key: "_getString",
                value: function(e) {
                    var t = this.head
                        , r = 1
                        , n = t.data;
                    for (e -= n.length; t = t.next; ) {
                        var s = t.data
                            , o = e > s.length ? s.length : e;
                        if (o === s.length ? n += s : n += s.slice(0, e),
                        0 == (e -= o)) {
                            o === s.length ? (++r,
                                t.next ? this.head = t.next : this.head = this.tail = null) : (this.head = t,
                                t.data = s.slice(o));
                            break
                        }
                        ++r
                    }
                    return this.length -= r,
                        n
                }
            }, {
                key: "_getBuffer",
                value: function(e) {
                    var t = c.allocUnsafe(e)
                        , r = this.head
                        , n = 1;
                    for (r.data.copy(t),
                             e -= r.data.length; r = r.next; ) {
                        var s = r.data
                            , o = e > s.length ? s.length : e;
                        if (s.copy(t, t.length - e, 0, o),
                        0 == (e -= o)) {
                            o === s.length ? (++n,
                                r.next ? this.head = r.next : this.head = this.tail = null) : (this.head = r,
                                r.data = s.slice(o));
                            break
                        }
                        ++n
                    }
                    return this.length -= n,
                        t
                }
            }, {
                key: l,
                value: function(e, t) {
                    return u(this, s(s({}, t), {}, {
                        depth: 0,
                        customInspect: !1
                    }))
                }
            }]) && i(t.prototype, r),
            n && i(t, n),
                Object.defineProperty(t, "prototype", {
                    writable: !1
                }),
                e
        }()
    }
        , {
            buffer: 195,
            util: 194
        }],
    220: [function(e, t, r) {
        (function(e) {
                (function() {
                        "use strict";
                        function r(e, t) {
                            s(e, t),
                                n(e)
                        }
                        function n(e) {
                            e._writableState && !e._writableState.emitClose || e._readableState && !e._readableState.emitClose || e.emit("close")
                        }
                        function s(e, t) {
                            e.emit("error", t)
                        }
                        t.exports = {
                            destroy: function(t, o) {
                                var i = this
                                    , a = this._readableState && this._readableState.destroyed
                                    , c = this._writableState && this._writableState.destroyed;
                                return a || c ? (o ? o(t) : t && (this._writableState ? this._writableState.errorEmitted || (this._writableState.errorEmitted = !0,
                                    e.nextTick(s, this, t)) : e.nextTick(s, this, t)),
                                    this) : (this._readableState && (this._readableState.destroyed = !0),
                                this._writableState && (this._writableState.destroyed = !0),
                                    this._destroy(t || null, (function(t) {
                                            !o && t ? i._writableState ? i._writableState.errorEmitted ? e.nextTick(n, i) : (i._writableState.errorEmitted = !0,
                                                e.nextTick(r, i, t)) : e.nextTick(r, i, t) : o ? (e.nextTick(n, i),
                                                o(t)) : e.nextTick(n, i)
                                        }
                                    )),
                                    this)
                            },
                            undestroy: function() {
                                this._readableState && (this._readableState.destroyed = !1,
                                    this._readableState.reading = !1,
                                    this._readableState.ended = !1,
                                    this._readableState.endEmitted = !1),
                                this._writableState && (this._writableState.destroyed = !1,
                                    this._writableState.ended = !1,
                                    this._writableState.ending = !1,
                                    this._writableState.finalCalled = !1,
                                    this._writableState.prefinished = !1,
                                    this._writableState.finished = !1,
                                    this._writableState.errorEmitted = !1)
                            },
                            errorOrDestroy: function(e, t) {
                                var r = e._readableState
                                    , n = e._writableState;
                                r && r.autoDestroy || n && n.autoDestroy ? e.destroy(t) : e.emit("error", t)
                            }
                        }
                    }
                ).call(this)
            }
        ).call(this, e("_process"))
    }
        , {
            _process: 211
        }],
    221: [function(e, t, r) {
        "use strict";
        var n = e("../../../errors").codes.ERR_STREAM_PREMATURE_CLOSE;
        function s() {}
        t.exports = function e(t, r, o) {
            if ("function" == typeof r)
                return e(t, null, r);
            r || (r = {}),
                o = function(e) {
                    var t = !1;
                    return function() {
                        if (!t) {
                            t = !0;
                            for (var r = arguments.length, n = new Array(r), s = 0; s < r; s++)
                                n[s] = arguments[s];
                            e.apply(this, n)
                        }
                    }
                }(o || s);
            var i = r.readable || !1 !== r.readable && t.readable
                , a = r.writable || !1 !== r.writable && t.writable
                , c = function() {
                t.writable || l()
            }
                , u = t._writableState && t._writableState.finished
                , l = function() {
                a = !1,
                    u = !0,
                i || o.call(t)
            }
                , d = t._readableState && t._readableState.endEmitted
                , f = function() {
                i = !1,
                    d = !0,
                a || o.call(t)
            }
                , p = function(e) {
                o.call(t, e)
            }
                , h = function() {
                var e;
                return i && !d ? (t._readableState && t._readableState.ended || (e = new n),
                    o.call(t, e)) : a && !u ? (t._writableState && t._writableState.ended || (e = new n),
                    o.call(t, e)) : void 0
            }
                , g = function() {
                t.req.on("finish", l)
            };
            return !function(e) {
                return e.setHeader && "function" == typeof e.abort
            }(t) ? a && !t._writableState && (t.on("end", c),
                t.on("close", c)) : (t.on("complete", l),
                t.on("abort", h),
                t.req ? g() : t.on("request", g)),
                t.on("end", f),
                t.on("finish", l),
            !1 !== r.error && t.on("error", p),
                t.on("close", h),
                function() {
                    t.removeListener("complete", l),
                        t.removeListener("abort", h),
                        t.removeListener("request", g),
                    t.req && t.req.removeListener("finish", l),
                        t.removeListener("end", c),
                        t.removeListener("close", c),
                        t.removeListener("finish", l),
                        t.removeListener("end", f),
                        t.removeListener("error", p),
                        t.removeListener("close", h)
                }
        }
    }
        , {
            "../../../errors": 212
        }],
    222: [function(e, t, r) {
        t.exports = function() {
            throw new Error("Readable.from is not available in the browser")
        }
    }
        , {}],
    223: [function(e, t, r) {
        "use strict";
        var n;
        var s = e("../../../errors").codes
            , o = s.ERR_MISSING_ARGS
            , i = s.ERR_STREAM_DESTROYED;
        function a(e) {
            if (e)
                throw e
        }
        function c(e) {
            e()
        }
        function u(e, t) {
            return e.pipe(t)
        }
        t.exports = function() {
            for (var t = arguments.length, r = new Array(t), s = 0; s < t; s++)
                r[s] = arguments[s];
            var l, d = function(e) {
                return e.length ? "function" != typeof e[e.length - 1] ? a : e.pop() : a
            }(r);
            if (Array.isArray(r[0]) && (r = r[0]),
            r.length < 2)
                throw new o("streams");
            var f = r.map((function(t, s) {
                    var o = s < r.length - 1;
                    return function(t, r, s, o) {
                        o = function(e) {
                            var t = !1;
                            return function() {
                                t || (t = !0,
                                    e.apply(void 0, arguments))
                            }
                        }(o);
                        var a = !1;
                        t.on("close", (function() {
                                a = !0
                            }
                        )),
                        void 0 === n && (n = e("./end-of-stream")),
                            n(t, {
                                readable: r,
                                writable: s
                            }, (function(e) {
                                    if (e)
                                        return o(e);
                                    a = !0,
                                        o()
                                }
                            ));
                        var c = !1;
                        return function(e) {
                            if (!a && !c)
                                return c = !0,
                                    function(e) {
                                        return e.setHeader && "function" == typeof e.abort
                                    }(t) ? t.abort() : "function" == typeof t.destroy ? t.destroy() : void o(e || new i("pipe"))
                        }
                    }(t, o, s > 0, (function(e) {
                            l || (l = e),
                            e && f.forEach(c),
                            o || (f.forEach(c),
                                d(l))
                        }
                    ))
                }
            ));
            return r.reduce(u)
        }
    }
        , {
            "../../../errors": 212,
            "./end-of-stream": 221
        }],
    224: [function(e, t, r) {
        "use strict";
        var n = e("../../../errors").codes.ERR_INVALID_OPT_VALUE;
        t.exports = {
            getHighWaterMark: function(e, t, r, s) {
                var o = function(e, t, r) {
                    return null != e.highWaterMark ? e.highWaterMark : t ? e[r] : null
                }(t, s, r);
                if (null != o) {
                    if (!isFinite(o) || Math.floor(o) !== o || o < 0)
                        throw new n(s ? r : "highWaterMark",o);
                    return Math.floor(o)
                }
                return e.objectMode ? 16 : 16384
            }
        }
    }
        , {
            "../../../errors": 212
        }],
    225: [function(e, t, r) {
        t.exports = e("events").EventEmitter
    }
        , {
            events: 200
        }],
    226: [function(e, t, r) {
        (r = t.exports = e("./lib/_stream_readable.js")).Stream = r,
            r.Readable = r,
            r.Writable = e("./lib/_stream_writable.js"),
            r.Duplex = e("./lib/_stream_duplex.js"),
            r.Transform = e("./lib/_stream_transform.js"),
            r.PassThrough = e("./lib/_stream_passthrough.js"),
            r.finished = e("./lib/internal/streams/end-of-stream.js"),
            r.pipeline = e("./lib/internal/streams/pipeline.js")
    }
        , {
            "./lib/_stream_duplex.js": 213,
            "./lib/_stream_passthrough.js": 214,
            "./lib/_stream_readable.js": 215,
            "./lib/_stream_transform.js": 216,
            "./lib/_stream_writable.js": 217,
            "./lib/internal/streams/end-of-stream.js": 221,
            "./lib/internal/streams/pipeline.js": 223
        }],
    227: [function(e, t, r) {
        /*! safe-buffer. MIT License. Feross Aboukhadijeh <https://feross.org/opensource> */
        var n = e("buffer")
            , s = n.Buffer;
        function o(e, t) {
            for (var r in e)
                t[r] = e[r]
        }
        function i(e, t, r) {
            return s(e, t, r)
        }
        s.from && s.alloc && s.allocUnsafe && s.allocUnsafeSlow ? t.exports = n : (o(n, r),
            r.Buffer = i),
            i.prototype = Object.create(s.prototype),
            o(s, i),
            i.from = function(e, t, r) {
                if ("number" == typeof e)
                    throw new TypeError("Argument must not be a number");
                return s(e, t, r)
            }
            ,
            i.alloc = function(e, t, r) {
                if ("number" != typeof e)
                    throw new TypeError("Argument must be a number");
                var n = s(e);
                return void 0 !== t ? "string" == typeof r ? n.fill(t, r) : n.fill(t) : n.fill(0),
                    n
            }
            ,
            i.allocUnsafe = function(e) {
                if ("number" != typeof e)
                    throw new TypeError("Argument must be a number");
                return s(e)
            }
            ,
            i.allocUnsafeSlow = function(e) {
                if ("number" != typeof e)
                    throw new TypeError("Argument must be a number");
                return n.SlowBuffer(e)
            }
    }
        , {
            buffer: 195
        }],
    228: [function(e, t, r) {
        const n = Symbol("SemVer ANY");
        class s {
            static get ANY() {
                return n
            }
            constructor(e, t) {
                if (t = o(t),
                e instanceof s) {
                    if (e.loose === !!t.loose)
                        return e;
                    e = e.value
                }
                e = e.trim().split(/\s+/).join(" "),
                    u("comparator", e, t),
                    this.options = t,
                    this.loose = !!t.loose,
                    this.parse(e),
                    this.semver === n ? this.value = "" : this.value = this.operator + this.semver.version,
                    u("comp", this)
            }
            parse(e) {
                const t = this.options.loose ? i[a.COMPARATORLOOSE] : i[a.COMPARATOR]
                    , r = e.match(t);
                if (!r)
                    throw new TypeError(`Invalid comparator: ${e}`);
                this.operator = void 0 !== r[1] ? r[1] : "",
                "=" === this.operator && (this.operator = ""),
                    r[2] ? this.semver = new l(r[2],this.options.loose) : this.semver = n
            }
            toString() {
                return this.value
            }
            test(e) {
                if (u("Comparator.test", e, this.options.loose),
                this.semver === n || e === n)
                    return !0;
                if ("string" == typeof e)
                    try {
                        e = new l(e,this.options)
                    } catch (e) {
                        return !1
                    }
                return c(e, this.operator, this.semver, this.options)
            }
            intersects(e, t) {
                if (!(e instanceof s))
                    throw new TypeError("a Comparator is required");
                return "" === this.operator ? "" === this.value || new d(e.value,t).test(this.value) : "" === e.operator ? "" === e.value || new d(this.value,t).test(e.semver) : (!(t = o(t)).includePrerelease || "<0.0.0-0" !== this.value && "<0.0.0-0" !== e.value) && (!(!t.includePrerelease && (this.value.startsWith("<0.0.0") || e.value.startsWith("<0.0.0"))) && (!(!this.operator.startsWith(">") || !e.operator.startsWith(">")) || (!(!this.operator.startsWith("<") || !e.operator.startsWith("<")) || (!(this.semver.version !== e.semver.version || !this.operator.includes("=") || !e.operator.includes("=")) || (!!(c(this.semver, "<", e.semver, t) && this.operator.startsWith(">") && e.operator.startsWith("<")) || !!(c(this.semver, ">", e.semver, t) && this.operator.startsWith("<") && e.operator.startsWith(">")))))))
            }
        }
        t.exports = s;
        const o = e("../internal/parse-options")
            , {safeRe: i, t: a} = e("../internal/re")
            , c = e("../functions/cmp")
            , u = e("../internal/debug")
            , l = e("./semver")
            , d = e("./range")
    }
        , {
            "../functions/cmp": 232,
            "../internal/debug": 257,
            "../internal/parse-options": 260,
            "../internal/re": 261,
            "./range": 229,
            "./semver": 230
        }],
    229: [function(e, t, r) {
        const n = /\s+/g;
        class s {
            constructor(e, t) {
                if (t = i(t),
                e instanceof s)
                    return e.loose === !!t.loose && e.includePrerelease === !!t.includePrerelease ? e : new s(e.raw,t);
                if (e instanceof a)
                    return this.raw = e.value,
                        this.set = [[e]],
                        this.formatted = void 0,
                        this;
                if (this.options = t,
                    this.loose = !!t.loose,
                    this.includePrerelease = !!t.includePrerelease,
                    this.raw = e.trim().replace(n, " "),
                    this.set = this.raw.split("||").map((e => this.parseRange(e.trim()))).filter((e => e.length)),
                    !this.set.length)
                    throw new TypeError(`Invalid SemVer Range: ${this.raw}`);
                if (this.set.length > 1) {
                    const e = this.set[0];
                    if (this.set = this.set.filter((e => !b(e[0]))),
                    0 === this.set.length)
                        this.set = [e];
                    else if (this.set.length > 1)
                        for (const e of this.set)
                            if (1 === e.length && y(e[0])) {
                                this.set = [e];
                                break
                            }
                }
                this.formatted = void 0
            }
            get range() {
                if (void 0 === this.formatted) {
                    this.formatted = "";
                    for (let e = 0; e < this.set.length; e++) {
                        e > 0 && (this.formatted += "||");
                        const t = this.set[e];
                        for (let e = 0; e < t.length; e++)
                            e > 0 && (this.formatted += " "),
                                this.formatted += t[e].toString().trim()
                    }
                }
                return this.formatted
            }
            format() {
                return this.range
            }
            toString() {
                return this.range
            }
            parseRange(e) {
                const t = ((this.options.includePrerelease && g) | (this.options.loose && m)) + ":" + e
                    , r = o.get(t);
                if (r)
                    return r;
                const n = this.options.loose
                    , s = n ? l[d.HYPHENRANGELOOSE] : l[d.HYPHENRANGE];
                e = e.replace(s, C(this.options.includePrerelease)),
                    c("hyphen replace", e),
                    e = e.replace(l[d.COMPARATORTRIM], f),
                    c("comparator trim", e),
                    e = e.replace(l[d.TILDETRIM], p),
                    c("tilde trim", e),
                    e = e.replace(l[d.CARETTRIM], h),
                    c("caret trim", e);
                let i = e.split(" ").map((e => v(e, this.options))).join(" ").split(/\s+/).map((e => T(e, this.options)));
                n && (i = i.filter((e => (c("loose invalid filter", e, this.options),
                    !!e.match(l[d.COMPARATORLOOSE]))))),
                    c("range list", i);
                const u = new Map
                    , y = i.map((e => new a(e,this.options)));
                for (const e of y) {
                    if (b(e))
                        return [e];
                    u.set(e.value, e)
                }
                u.size > 1 && u.has("") && u.delete("");
                const w = [...u.values()];
                return o.set(t, w),
                    w
            }
            intersects(e, t) {
                if (!(e instanceof s))
                    throw new TypeError("a Range is required");
                return this.set.some((r => w(r, t) && e.set.some((e => w(e, t) && r.every((r => e.every((e => r.intersects(e, t)))))))))
            }
            test(e) {
                if (!e)
                    return !1;
                if ("string" == typeof e)
                    try {
                        e = new u(e,this.options)
                    } catch (e) {
                        return !1
                    }
                for (let t = 0; t < this.set.length; t++)
                    if (O(this.set[t], e, this.options))
                        return !0;
                return !1
            }
        }
        t.exports = s;
        const o = new (e("../internal/lrucache"))
            , i = e("../internal/parse-options")
            , a = e("./comparator")
            , c = e("../internal/debug")
            , u = e("./semver")
            , {safeRe: l, t: d, comparatorTrimReplace: f, tildeTrimReplace: p, caretTrimReplace: h} = e("../internal/re")
            , {FLAG_INCLUDE_PRERELEASE: g, FLAG_LOOSE: m} = e("../internal/constants")
            , b = e => "<0.0.0-0" === e.value
            , y = e => "" === e.value
            , w = (e, t) => {
            let r = !0;
            const n = e.slice();
            let s = n.pop();
            for (; r && n.length; )
                r = n.every((e => s.intersects(e, t))),
                    s = n.pop();
            return r
        }
            , v = (e, t) => (c("comp", e, t),
            e = j(e, t),
            c("caret", e),
            e = E(e, t),
            c("tildes", e),
            e = I(e, t),
            c("xrange", e),
            e = M(e, t),
            c("stars", e),
            e)
            , _ = e => !e || "x" === e.toLowerCase() || "*" === e
            , E = (e, t) => e.trim().split(/\s+/).map((e => S(e, t))).join(" ")
            , S = (e, t) => {
            const r = t.loose ? l[d.TILDELOOSE] : l[d.TILDE];
            return e.replace(r, ( (t, r, n, s, o) => {
                    let i;
                    return c("tilde", e, t, r, n, s, o),
                        _(r) ? i = "" : _(n) ? i = `>=${r}.0.0 <${+r + 1}.0.0-0` : _(s) ? i = `>=${r}.${n}.0 <${r}.${+n + 1}.0-0` : o ? (c("replaceTilde pr", o),
                            i = `>=${r}.${n}.${s}-${o} <${r}.${+n + 1}.0-0`) : i = `>=${r}.${n}.${s} <${r}.${+n + 1}.0-0`,
                        c("tilde return", i),
                        i
                }
            ))
        }
            , j = (e, t) => e.trim().split(/\s+/).map((e => R(e, t))).join(" ")
            , R = (e, t) => {
            c("caret", e, t);
            const r = t.loose ? l[d.CARETLOOSE] : l[d.CARET]
                , n = t.includePrerelease ? "-0" : "";
            return e.replace(r, ( (t, r, s, o, i) => {
                    let a;
                    return c("caret", e, t, r, s, o, i),
                        _(r) ? a = "" : _(s) ? a = `>=${r}.0.0${n} <${+r + 1}.0.0-0` : _(o) ? a = "0" === r ? `>=${r}.${s}.0${n} <${r}.${+s + 1}.0-0` : `>=${r}.${s}.0${n} <${+r + 1}.0.0-0` : i ? (c("replaceCaret pr", i),
                            a = "0" === r ? "0" === s ? `>=${r}.${s}.${o}-${i} <${r}.${s}.${+o + 1}-0` : `>=${r}.${s}.${o}-${i} <${r}.${+s + 1}.0-0` : `>=${r}.${s}.${o}-${i} <${+r + 1}.0.0-0`) : (c("no pr"),
                            a = "0" === r ? "0" === s ? `>=${r}.${s}.${o}${n} <${r}.${s}.${+o + 1}-0` : `>=${r}.${s}.${o}${n} <${r}.${+s + 1}.0-0` : `>=${r}.${s}.${o} <${+r + 1}.0.0-0`),
                        c("caret return", a),
                        a
                }
            ))
        }
            , I = (e, t) => (c("replaceXRanges", e, t),
            e.split(/\s+/).map((e => A(e, t))).join(" "))
            , A = (e, t) => {
            e = e.trim();
            const r = t.loose ? l[d.XRANGELOOSE] : l[d.XRANGE];
            return e.replace(r, ( (r, n, s, o, i, a) => {
                    c("xRange", e, r, n, s, o, i, a);
                    const u = _(s)
                        , l = u || _(o)
                        , d = l || _(i)
                        , f = d;
                    return "=" === n && f && (n = ""),
                        a = t.includePrerelease ? "-0" : "",
                        u ? r = ">" === n || "<" === n ? "<0.0.0-0" : "*" : n && f ? (l && (o = 0),
                            i = 0,
                            ">" === n ? (n = ">=",
                                l ? (s = +s + 1,
                                    o = 0,
                                    i = 0) : (o = +o + 1,
                                    i = 0)) : "<=" === n && (n = "<",
                                l ? s = +s + 1 : o = +o + 1),
                        "<" === n && (a = "-0"),
                            r = `${n + s}.${o}.${i}${a}`) : l ? r = `>=${s}.0.0${a} <${+s + 1}.0.0-0` : d && (r = `>=${s}.${o}.0${a} <${s}.${+o + 1}.0-0`),
                        c("xRange return", r),
                        r
                }
            ))
        }
            , M = (e, t) => (c("replaceStars", e, t),
            e.trim().replace(l[d.STAR], ""))
            , T = (e, t) => (c("replaceGTE0", e, t),
            e.trim().replace(l[t.includePrerelease ? d.GTE0PRE : d.GTE0], ""))
            , C = e => (t, r, n, s, o, i, a, c, u, l, d, f) => `${r = _(n) ? "" : _(s) ? `>=${n}.0.0${e ? "-0" : ""}` : _(o) ? `>=${n}.${s}.0${e ? "-0" : ""}` : i ? `>=${r}` : `>=${r}${e ? "-0" : ""}`} ${c = _(u) ? "" : _(l) ? `<${+u + 1}.0.0-0` : _(d) ? `<${u}.${+l + 1}.0-0` : f ? `<=${u}.${l}.${d}-${f}` : e ? `<${u}.${l}.${+d + 1}-0` : `<=${c}`}`.trim()
            , O = (e, t, r) => {
            for (let r = 0; r < e.length; r++)
                if (!e[r].test(t))
                    return !1;
            if (t.prerelease.length && !r.includePrerelease) {
                for (let r = 0; r < e.length; r++)
                    if (c(e[r].semver),
                    e[r].semver !== a.ANY && e[r].semver.prerelease.length > 0) {
                        const n = e[r].semver;
                        if (n.major === t.major && n.minor === t.minor && n.patch === t.patch)
                            return !0
                    }
                return !1
            }
            return !0
        }
    }
        , {
            "../internal/constants": 256,
            "../internal/debug": 257,
            "../internal/lrucache": 259,
            "../internal/parse-options": 260,
            "../internal/re": 261,
            "./comparator": 228,
            "./semver": 230
        }],
    230: [function(e, t, r) {
        const n = e("../internal/debug")
            , {MAX_LENGTH: s, MAX_SAFE_INTEGER: o} = e("../internal/constants")
            , {safeRe: i, t: a} = e("../internal/re")
            , c = e("../internal/parse-options")
            , {compareIdentifiers: u} = e("../internal/identifiers");
        class l {
            constructor(e, t) {
                if (t = c(t),
                e instanceof l) {
                    if (e.loose === !!t.loose && e.includePrerelease === !!t.includePrerelease)
                        return e;
                    e = e.version
                } else if ("string" != typeof e)
                    throw new TypeError(`Invalid version. Must be a string. Got type "${typeof e}".`);
                if (e.length > s)
                    throw new TypeError(`version is longer than ${s} characters`);
                n("SemVer", e, t),
                    this.options = t,
                    this.loose = !!t.loose,
                    this.includePrerelease = !!t.includePrerelease;
                const r = e.trim().match(t.loose ? i[a.LOOSE] : i[a.FULL]);
                if (!r)
                    throw new TypeError(`Invalid Version: ${e}`);
                if (this.raw = e,
                    this.major = +r[1],
                    this.minor = +r[2],
                    this.patch = +r[3],
                this.major > o || this.major < 0)
                    throw new TypeError("Invalid major version");
                if (this.minor > o || this.minor < 0)
                    throw new TypeError("Invalid minor version");
                if (this.patch > o || this.patch < 0)
                    throw new TypeError("Invalid patch version");
                r[4] ? this.prerelease = r[4].split(".").map((e => {
                        if (/^[0-9]+$/.test(e)) {
                            const t = +e;
                            if (t >= 0 && t < o)
                                return t
                        }
                        return e
                    }
                )) : this.prerelease = [],
                    this.build = r[5] ? r[5].split(".") : [],
                    this.format()
            }
            format() {
                return this.version = `${this.major}.${this.minor}.${this.patch}`,
                this.prerelease.length && (this.version += `-${this.prerelease.join(".")}`),
                    this.version
            }
            toString() {
                return this.version
            }
            compare(e) {
                if (n("SemVer.compare", this.version, this.options, e),
                    !(e instanceof l)) {
                    if ("string" == typeof e && e === this.version)
                        return 0;
                    e = new l(e,this.options)
                }
                return e.version === this.version ? 0 : this.compareMain(e) || this.comparePre(e)
            }
            compareMain(e) {
                return e instanceof l || (e = new l(e,this.options)),
                u(this.major, e.major) || u(this.minor, e.minor) || u(this.patch, e.patch)
            }
            comparePre(e) {
                if (e instanceof l || (e = new l(e,this.options)),
                this.prerelease.length && !e.prerelease.length)
                    return -1;
                if (!this.prerelease.length && e.prerelease.length)
                    return 1;
                if (!this.prerelease.length && !e.prerelease.length)
                    return 0;
                let t = 0;
                do {
                    const r = this.prerelease[t]
                        , s = e.prerelease[t];
                    if (n("prerelease compare", t, r, s),
                    void 0 === r && void 0 === s)
                        return 0;
                    if (void 0 === s)
                        return 1;
                    if (void 0 === r)
                        return -1;
                    if (r !== s)
                        return u(r, s)
                } while (++t)
            }
            compareBuild(e) {
                e instanceof l || (e = new l(e,this.options));
                let t = 0;
                do {
                    const r = this.build[t]
                        , s = e.build[t];
                    if (n("build compare", t, r, s),
                    void 0 === r && void 0 === s)
                        return 0;
                    if (void 0 === s)
                        return 1;
                    if (void 0 === r)
                        return -1;
                    if (r !== s)
                        return u(r, s)
                } while (++t)
            }
            inc(e, t, r) {
                switch (e) {
                    case "premajor":
                        this.prerelease.length = 0,
                            this.patch = 0,
                            this.minor = 0,
                            this.major++,
                            this.inc("pre", t, r);
                        break;
                    case "preminor":
                        this.prerelease.length = 0,
                            this.patch = 0,
                            this.minor++,
                            this.inc("pre", t, r);
                        break;
                    case "prepatch":
                        this.prerelease.length = 0,
                            this.inc("patch", t, r),
                            this.inc("pre", t, r);
                        break;
                    case "prerelease":
                        0 === this.prerelease.length && this.inc("patch", t, r),
                            this.inc("pre", t, r);
                        break;
                    case "major":
                        0 === this.minor && 0 === this.patch && 0 !== this.prerelease.length || this.major++,
                            this.minor = 0,
                            this.patch = 0,
                            this.prerelease = [];
                        break;
                    case "minor":
                        0 === this.patch && 0 !== this.prerelease.length || this.minor++,
                            this.patch = 0,
                            this.prerelease = [];
                        break;
                    case "patch":
                        0 === this.prerelease.length && this.patch++,
                            this.prerelease = [];
                        break;
                    case "pre":
                    {
                        const e = Number(r) ? 1 : 0;
                        if (!t && !1 === r)
                            throw new Error("invalid increment argument: identifier is empty");
                        if (0 === this.prerelease.length)
                            this.prerelease = [e];
                        else {
                            let n = this.prerelease.length;
                            for (; --n >= 0; )
                                "number" == typeof this.prerelease[n] && (this.prerelease[n]++,
                                    n = -2);
                            if (-1 === n) {
                                if (t === this.prerelease.join(".") && !1 === r)
                                    throw new Error("invalid increment argument: identifier already exists");
                                this.prerelease.push(e)
                            }
                        }
                        if (t) {
                            let n = [t, e];
                            !1 === r && (n = [t]),
                                0 === u(this.prerelease[0], t) ? isNaN(this.prerelease[1]) && (this.prerelease = n) : this.prerelease = n
                        }
                        break
                    }
                    default:
                        throw new Error(`invalid increment argument: ${e}`)
                }
                return this.raw = this.format(),
                this.build.length && (this.raw += `+${this.build.join(".")}`),
                    this
            }
        }
        t.exports = l
    }
        , {
            "../internal/constants": 256,
            "../internal/debug": 257,
            "../internal/identifiers": 258,
            "../internal/parse-options": 260,
            "../internal/re": 261
        }],
    231: [function(e, t, r) {
        const n = e("./parse");
        t.exports = (e, t) => {
            const r = n(e.trim().replace(/^[=v]+/, ""), t);
            return r ? r.version : null
        }
    }
        , {
            "./parse": 247
        }],
    232: [function(e, t, r) {
        const n = e("./eq")
            , s = e("./neq")
            , o = e("./gt")
            , i = e("./gte")
            , a = e("./lt")
            , c = e("./lte");
        t.exports = (e, t, r, u) => {
            switch (t) {
                case "===":
                    return "object" == typeof e && (e = e.version),
                    "object" == typeof r && (r = r.version),
                    e === r;
                case "!==":
                    return "object" == typeof e && (e = e.version),
                    "object" == typeof r && (r = r.version),
                    e !== r;
                case "":
                case "=":
                case "==":
                    return n(e, r, u);
                case "!=":
                    return s(e, r, u);
                case ">":
                    return o(e, r, u);
                case ">=":
                    return i(e, r, u);
                case "<":
                    return a(e, r, u);
                case "<=":
                    return c(e, r, u);
                default:
                    throw new TypeError(`Invalid operator: ${t}`)
            }
        }
    }
        , {
            "./eq": 238,
            "./gt": 239,
            "./gte": 240,
            "./lt": 242,
            "./lte": 243,
            "./neq": 246
        }],
    233: [function(e, t, r) {
        const n = e("../classes/semver")
            , s = e("./parse")
            , {safeRe: o, t: i} = e("../internal/re");
        t.exports = (e, t) => {
            if (e instanceof n)
                return e;
            if ("number" == typeof e && (e = String(e)),
            "string" != typeof e)
                return null;
            let r = null;
            if ((t = t || {}).rtl) {
                const n = t.includePrerelease ? o[i.COERCERTLFULL] : o[i.COERCERTL];
                let s;
                for (; (s = n.exec(e)) && (!r || r.index + r[0].length !== e.length); )
                    r && s.index + s[0].length === r.index + r[0].length || (r = s),
                        n.lastIndex = s.index + s[1].length + s[2].length;
                n.lastIndex = -1
            } else
                r = e.match(t.includePrerelease ? o[i.COERCEFULL] : o[i.COERCE]);
            if (null === r)
                return null;
            const a = r[2]
                , c = r[3] || "0"
                , u = r[4] || "0"
                , l = t.includePrerelease && r[5] ? `-${r[5]}` : ""
                , d = t.includePrerelease && r[6] ? `+${r[6]}` : "";
            return s(`${a}.${c}.${u}${l}${d}`, t)
        }
    }
        , {
            "../classes/semver": 230,
            "../internal/re": 261,
            "./parse": 247
        }],
    234: [function(e, t, r) {
        const n = e("../classes/semver");
        t.exports = (e, t, r) => {
            const s = new n(e,r)
                , o = new n(t,r);
            return s.compare(o) || s.compareBuild(o)
        }
    }
        , {
            "../classes/semver": 230
        }],
    235: [function(e, t, r) {
        const n = e("./compare");
        t.exports = (e, t) => n(e, t, !0)
    }
        , {
            "./compare": 236
        }],
    236: [function(e, t, r) {
        const n = e("../classes/semver");
        t.exports = (e, t, r) => new n(e,r).compare(new n(t,r))
    }
        , {
            "../classes/semver": 230
        }],
    237: [function(e, t, r) {
        const n = e("./parse.js");
        t.exports = (e, t) => {
            const r = n(e, null, !0)
                , s = n(t, null, !0)
                , o = r.compare(s);
            if (0 === o)
                return null;
            const i = o > 0
                , a = i ? r : s
                , c = i ? s : r
                , u = !!a.prerelease.length;
            if (!!c.prerelease.length && !u)
                return c.patch || c.minor ? a.patch ? "patch" : a.minor ? "minor" : "major" : "major";
            const l = u ? "pre" : "";
            return r.major !== s.major ? l + "major" : r.minor !== s.minor ? l + "minor" : r.patch !== s.patch ? l + "patch" : "prerelease"
        }
    }
        , {
            "./parse.js": 247
        }],
    238: [function(e, t, r) {
        const n = e("./compare");
        t.exports = (e, t, r) => 0 === n(e, t, r)
    }
        , {
            "./compare": 236
        }],
    239: [function(e, t, r) {
        const n = e("./compare");
        t.exports = (e, t, r) => n(e, t, r) > 0
    }
        , {
            "./compare": 236
        }],
    240: [function(e, t, r) {
        const n = e("./compare");
        t.exports = (e, t, r) => n(e, t, r) >= 0
    }
        , {
            "./compare": 236
        }],
    241: [function(e, t, r) {
        const n = e("../classes/semver");
        t.exports = (e, t, r, s, o) => {
            "string" == typeof r && (o = s,
                s = r,
                r = void 0);
            try {
                return new n(e instanceof n ? e.version : e,r).inc(t, s, o).version
            } catch (e) {
                return null
            }
        }
    }
        , {
            "../classes/semver": 230
        }],
    242: [function(e, t, r) {
        const n = e("./compare");
        t.exports = (e, t, r) => n(e, t, r) < 0
    }
        , {
            "./compare": 236
        }],
    243: [function(e, t, r) {
        const n = e("./compare");
        t.exports = (e, t, r) => n(e, t, r) <= 0
    }
        , {
            "./compare": 236
        }],
    244: [function(e, t, r) {
        const n = e("../classes/semver");
        t.exports = (e, t) => new n(e,t).major
    }
        , {
            "../classes/semver": 230
        }],
    245: [function(e, t, r) {
        const n = e("../classes/semver");
        t.exports = (e, t) => new n(e,t).minor
    }
        , {
            "../classes/semver": 230
        }],
    246: [function(e, t, r) {
        const n = e("./compare");
        t.exports = (e, t, r) => 0 !== n(e, t, r)
    }
        , {
            "./compare": 236
        }],
    247: [function(e, t, r) {
        const n = e("../classes/semver");
        t.exports = (e, t, r=!1) => {
            if (e instanceof n)
                return e;
            try {
                return new n(e,t)
            } catch (e) {
                if (!r)
                    return null;
                throw e
            }
        }
    }
        , {
            "../classes/semver": 230
        }],
    248: [function(e, t, r) {
        const n = e("../classes/semver");
        t.exports = (e, t) => new n(e,t).patch
    }
        , {
            "../classes/semver": 230
        }],
    249: [function(e, t, r) {
        const n = e("./parse");
        t.exports = (e, t) => {
            const r = n(e, t);
            return r && r.prerelease.length ? r.prerelease : null
        }
    }
        , {
            "./parse": 247
        }],
    250: [function(e, t, r) {
        const n = e("./compare");
        t.exports = (e, t, r) => n(t, e, r)
    }
        , {
            "./compare": 236
        }],
    251: [function(e, t, r) {
        const n = e("./compare-build");
        t.exports = (e, t) => e.sort(( (e, r) => n(r, e, t)))
    }
        , {
            "./compare-build": 234
        }],
    252: [function(e, t, r) {
        const n = e("../classes/range");
        t.exports = (e, t, r) => {
            try {
                t = new n(t,r)
            } catch (e) {
                return !1
            }
            return t.test(e)
        }
    }
        , {
            "../classes/range": 229
        }],
    253: [function(e, t, r) {
        const n = e("./compare-build");
        t.exports = (e, t) => e.sort(( (e, r) => n(e, r, t)))
    }
        , {
            "./compare-build": 234
        }],
    254: [function(e, t, r) {
        const n = e("./parse");
        t.exports = (e, t) => {
            const r = n(e, t);
            return r ? r.version : null
        }
    }
        , {
            "./parse": 247
        }],
    255: [function(e, t, r) {
        const n = e("./internal/re")
            , s = e("./internal/constants")
            , o = e("./classes/semver")
            , i = e("./internal/identifiers")
            , a = e("./functions/parse")
            , c = e("./functions/valid")
            , u = e("./functions/clean")
            , l = e("./functions/inc")
            , d = e("./functions/diff")
            , f = e("./functions/major")
            , p = e("./functions/minor")
            , h = e("./functions/patch")
            , g = e("./functions/prerelease")
            , m = e("./functions/compare")
            , b = e("./functions/rcompare")
            , y = e("./functions/compare-loose")
            , w = e("./functions/compare-build")
            , v = e("./functions/sort")
            , _ = e("./functions/rsort")
            , E = e("./functions/gt")
            , S = e("./functions/lt")
            , j = e("./functions/eq")
            , R = e("./functions/neq")
            , I = e("./functions/gte")
            , A = e("./functions/lte")
            , M = e("./functions/cmp")
            , T = e("./functions/coerce")
            , C = e("./classes/comparator")
            , O = e("./classes/range")
            , x = e("./functions/satisfies")
            , N = e("./ranges/to-comparators")
            , P = e("./ranges/max-satisfying")
            , k = e("./ranges/min-satisfying")
            , L = e("./ranges/min-version")
            , D = e("./ranges/valid")
            , B = e("./ranges/outside")
            , $ = e("./ranges/gtr")
            , U = e("./ranges/ltr")
            , F = e("./ranges/intersects")
            , W = e("./ranges/simplify")
            , z = e("./ranges/subset");
        t.exports = {
            parse: a,
            valid: c,
            clean: u,
            inc: l,
            diff: d,
            major: f,
            minor: p,
            patch: h,
            prerelease: g,
            compare: m,
            rcompare: b,
            compareLoose: y,
            compareBuild: w,
            sort: v,
            rsort: _,
            gt: E,
            lt: S,
            eq: j,
            neq: R,
            gte: I,
            lte: A,
            cmp: M,
            coerce: T,
            Comparator: C,
            Range: O,
            satisfies: x,
            toComparators: N,
            maxSatisfying: P,
            minSatisfying: k,
            minVersion: L,
            validRange: D,
            outside: B,
            gtr: $,
            ltr: U,
            intersects: F,
            simplifyRange: W,
            subset: z,
            SemVer: o,
            re: n.re,
            src: n.src,
            tokens: n.t,
            SEMVER_SPEC_VERSION: s.SEMVER_SPEC_VERSION,
            RELEASE_TYPES: s.RELEASE_TYPES,
            compareIdentifiers: i.compareIdentifiers,
            rcompareIdentifiers: i.rcompareIdentifiers
        }
    }
        , {
            "./classes/comparator": 228,
            "./classes/range": 229,
            "./classes/semver": 230,
            "./functions/clean": 231,
            "./functions/cmp": 232,
            "./functions/coerce": 233,
            "./functions/compare": 236,
            "./functions/compare-build": 234,
            "./functions/compare-loose": 235,
            "./functions/diff": 237,
            "./functions/eq": 238,
            "./functions/gt": 239,
            "./functions/gte": 240,
            "./functions/inc": 241,
            "./functions/lt": 242,
            "./functions/lte": 243,
            "./functions/major": 244,
            "./functions/minor": 245,
            "./functions/neq": 246,
            "./functions/parse": 247,
            "./functions/patch": 248,
            "./functions/prerelease": 249,
            "./functions/rcompare": 250,
            "./functions/rsort": 251,
            "./functions/satisfies": 252,
            "./functions/sort": 253,
            "./functions/valid": 254,
            "./internal/constants": 256,
            "./internal/identifiers": 258,
            "./internal/re": 261,
            "./ranges/gtr": 262,
            "./ranges/intersects": 263,
            "./ranges/ltr": 264,
            "./ranges/max-satisfying": 265,
            "./ranges/min-satisfying": 266,
            "./ranges/min-version": 267,
            "./ranges/outside": 268,
            "./ranges/simplify": 269,
            "./ranges/subset": 270,
            "./ranges/to-comparators": 271,
            "./ranges/valid": 272
        }],
    256: [function(e, t, r) {
        const n = Number.MAX_SAFE_INTEGER || 9007199254740991;
        t.exports = {
            MAX_LENGTH: 256,
            MAX_SAFE_COMPONENT_LENGTH: 16,
            MAX_SAFE_BUILD_LENGTH: 250,
            MAX_SAFE_INTEGER: n,
            RELEASE_TYPES: ["major", "premajor", "minor", "preminor", "patch", "prepatch", "prerelease"],
            SEMVER_SPEC_VERSION: "2.0.0",
            FLAG_INCLUDE_PRERELEASE: 1,
            FLAG_LOOSE: 2
        }
    }
        , {}],
    257: [function(e, t, r) {
        (function(e) {
                (function() {
                        const r = ("object" == typeof e && e.env,
                                () => {}
                        );
                        t.exports = r
                    }
                ).call(this)
            }
        ).call(this, e("_process"))
    }
        , {
            _process: 211
        }],
    258: [function(e, t, r) {
        const n = /^[0-9]+$/
            , s = (e, t) => {
                const r = n.test(e)
                    , s = n.test(t);
                return r && s && (e = +e,
                    t = +t),
                    e === t ? 0 : r && !s ? -1 : s && !r ? 1 : e < t ? -1 : 1
            }
        ;
        t.exports = {
            compareIdentifiers: s,
            rcompareIdentifiers: (e, t) => s(t, e)
        }
    }
        , {}],
    259: [function(e, t, r) {
        t.exports = class {
            constructor() {
                this.max = 1e3,
                    this.map = new Map
            }
            get(e) {
                const t = this.map.get(e);
                return void 0 === t ? void 0 : (this.map.delete(e),
                    this.map.set(e, t),
                    t)
            }
            delete(e) {
                return this.map.delete(e)
            }
            set(e, t) {
                if (!this.delete(e) && void 0 !== t) {
                    if (this.map.size >= this.max) {
                        const e = this.map.keys().next().value;
                        this.delete(e)
                    }
                    this.map.set(e, t)
                }
                return this
            }
        }
    }
        , {}],
    260: [function(e, t, r) {
        const n = Object.freeze({
            loose: !0
        })
            , s = Object.freeze({});
        t.exports = e => e ? "object" != typeof e ? n : e : s
    }
        , {}],
    261: [function(e, t, r) {
        const {MAX_SAFE_COMPONENT_LENGTH: n, MAX_SAFE_BUILD_LENGTH: s, MAX_LENGTH: o} = e("./constants")
            , i = e("./debug")
            , a = (r = t.exports = {}).re = []
            , c = r.safeRe = []
            , u = r.src = []
            , l = r.t = {};
        let d = 0;
        const f = "[a-zA-Z0-9-]"
            , p = [["\\s", 1], ["\\d", o], [f, s]]
            , h = (e, t, r) => {
                const n = (e => {
                        for (const [t,r] of p)
                            e = e.split(`${t}*`).join(`${t}{0,${r}}`).split(`${t}+`).join(`${t}{1,${r}}`);
                        return e
                    }
                )(t)
                    , s = d++;
                i(e, s, t),
                    l[e] = s,
                    u[s] = t,
                    a[s] = new RegExp(t,r ? "g" : void 0),
                    c[s] = new RegExp(n,r ? "g" : void 0)
            }
        ;
        h("NUMERICIDENTIFIER", "0|[1-9]\\d*"),
            h("NUMERICIDENTIFIERLOOSE", "\\d+"),
            h("NONNUMERICIDENTIFIER", `\\d*[a-zA-Z-]${f}*`),
            h("MAINVERSION", `(${u[l.NUMERICIDENTIFIER]})\\.(${u[l.NUMERICIDENTIFIER]})\\.(${u[l.NUMERICIDENTIFIER]})`),
            h("MAINVERSIONLOOSE", `(${u[l.NUMERICIDENTIFIERLOOSE]})\\.(${u[l.NUMERICIDENTIFIERLOOSE]})\\.(${u[l.NUMERICIDENTIFIERLOOSE]})`),
            h("PRERELEASEIDENTIFIER", `(?:${u[l.NUMERICIDENTIFIER]}|${u[l.NONNUMERICIDENTIFIER]})`),
            h("PRERELEASEIDENTIFIERLOOSE", `(?:${u[l.NUMERICIDENTIFIERLOOSE]}|${u[l.NONNUMERICIDENTIFIER]})`),
            h("PRERELEASE", `(?:-(${u[l.PRERELEASEIDENTIFIER]}(?:\\.${u[l.PRERELEASEIDENTIFIER]})*))`),
            h("PRERELEASELOOSE", `(?:-?(${u[l.PRERELEASEIDENTIFIERLOOSE]}(?:\\.${u[l.PRERELEASEIDENTIFIERLOOSE]})*))`),
            h("BUILDIDENTIFIER", `${f}+`),
            h("BUILD", `(?:\\+(${u[l.BUILDIDENTIFIER]}(?:\\.${u[l.BUILDIDENTIFIER]})*))`),
            h("FULLPLAIN", `v?${u[l.MAINVERSION]}${u[l.PRERELEASE]}?${u[l.BUILD]}?`),
            h("FULL", `^${u[l.FULLPLAIN]}$`),
            h("LOOSEPLAIN", `[v=\\s]*${u[l.MAINVERSIONLOOSE]}${u[l.PRERELEASELOOSE]}?${u[l.BUILD]}?`),
            h("LOOSE", `^${u[l.LOOSEPLAIN]}$`),
            h("GTLT", "((?:<|>)?=?)"),
            h("XRANGEIDENTIFIERLOOSE", `${u[l.NUMERICIDENTIFIERLOOSE]}|x|X|\\*`),
            h("XRANGEIDENTIFIER", `${u[l.NUMERICIDENTIFIER]}|x|X|\\*`),
            h("XRANGEPLAIN", `[v=\\s]*(${u[l.XRANGEIDENTIFIER]})(?:\\.(${u[l.XRANGEIDENTIFIER]})(?:\\.(${u[l.XRANGEIDENTIFIER]})(?:${u[l.PRERELEASE]})?${u[l.BUILD]}?)?)?`),
            h("XRANGEPLAINLOOSE", `[v=\\s]*(${u[l.XRANGEIDENTIFIERLOOSE]})(?:\\.(${u[l.XRANGEIDENTIFIERLOOSE]})(?:\\.(${u[l.XRANGEIDENTIFIERLOOSE]})(?:${u[l.PRERELEASELOOSE]})?${u[l.BUILD]}?)?)?`),
            h("XRANGE", `^${u[l.GTLT]}\\s*${u[l.XRANGEPLAIN]}$`),
            h("XRANGELOOSE", `^${u[l.GTLT]}\\s*${u[l.XRANGEPLAINLOOSE]}$`),
            h("COERCEPLAIN", `(^|[^\\d])(\\d{1,${n}})(?:\\.(\\d{1,${n}}))?(?:\\.(\\d{1,${n}}))?`),
            h("COERCE", `${u[l.COERCEPLAIN]}(?:$|[^\\d])`),
            h("COERCEFULL", u[l.COERCEPLAIN] + `(?:${u[l.PRERELEASE]})?` + `(?:${u[l.BUILD]})?(?:$|[^\\d])`),
            h("COERCERTL", u[l.COERCE], !0),
            h("COERCERTLFULL", u[l.COERCEFULL], !0),
            h("LONETILDE", "(?:~>?)"),
            h("TILDETRIM", `(\\s*)${u[l.LONETILDE]}\\s+`, !0),
            r.tildeTrimReplace = "$1~",
            h("TILDE", `^${u[l.LONETILDE]}${u[l.XRANGEPLAIN]}$`),
            h("TILDELOOSE", `^${u[l.LONETILDE]}${u[l.XRANGEPLAINLOOSE]}$`),
            h("LONECARET", "(?:\\^)"),
            h("CARETTRIM", `(\\s*)${u[l.LONECARET]}\\s+`, !0),
            r.caretTrimReplace = "$1^",
            h("CARET", `^${u[l.LONECARET]}${u[l.XRANGEPLAIN]}$`),
            h("CARETLOOSE", `^${u[l.LONECARET]}${u[l.XRANGEPLAINLOOSE]}$`),
            h("COMPARATORLOOSE", `^${u[l.GTLT]}\\s*(${u[l.LOOSEPLAIN]})$|^$`),
            h("COMPARATOR", `^${u[l.GTLT]}\\s*(${u[l.FULLPLAIN]})$|^$`),
            h("COMPARATORTRIM", `(\\s*)${u[l.GTLT]}\\s*(${u[l.LOOSEPLAIN]}|${u[l.XRANGEPLAIN]})`, !0),
            r.comparatorTrimReplace = "$1$2$3",
            h("HYPHENRANGE", `^\\s*(${u[l.XRANGEPLAIN]})\\s+-\\s+(${u[l.XRANGEPLAIN]})\\s*$`),
            h("HYPHENRANGELOOSE", `^\\s*(${u[l.XRANGEPLAINLOOSE]})\\s+-\\s+(${u[l.XRANGEPLAINLOOSE]})\\s*$`),
            h("STAR", "(<|>)?=?\\s*\\*"),
            h("GTE0", "^\\s*>=\\s*0\\.0\\.0\\s*$"),
            h("GTE0PRE", "^\\s*>=\\s*0\\.0\\.0-0\\s*$")
    }
        , {
            "./constants": 256,
            "./debug": 257
        }],
    262: [function(e, t, r) {
        const n = e("./outside");
        t.exports = (e, t, r) => n(e, t, ">", r)
    }
        , {
            "./outside": 268
        }],
    263: [function(e, t, r) {
        const n = e("../classes/range");
        t.exports = (e, t, r) => (e = new n(e,r),
            t = new n(t,r),
            e.intersects(t, r))
    }
        , {
            "../classes/range": 229
        }],
    264: [function(e, t, r) {
        const n = e("./outside");
        t.exports = (e, t, r) => n(e, t, "<", r)
    }
        , {
            "./outside": 268
        }],
    265: [function(e, t, r) {
        const n = e("../classes/semver")
            , s = e("../classes/range");
        t.exports = (e, t, r) => {
            let o = null
                , i = null
                , a = null;
            try {
                a = new s(t,r)
            } catch (e) {
                return null
            }
            return e.forEach((e => {
                    a.test(e) && (o && -1 !== i.compare(e) || (o = e,
                        i = new n(o,r)))
                }
            )),
                o
        }
    }
        , {
            "../classes/range": 229,
            "../classes/semver": 230
        }],
    266: [function(e, t, r) {
        const n = e("../classes/semver")
            , s = e("../classes/range");
        t.exports = (e, t, r) => {
            let o = null
                , i = null
                , a = null;
            try {
                a = new s(t,r)
            } catch (e) {
                return null
            }
            return e.forEach((e => {
                    a.test(e) && (o && 1 !== i.compare(e) || (o = e,
                        i = new n(o,r)))
                }
            )),
                o
        }
    }
        , {
            "../classes/range": 229,
            "../classes/semver": 230
        }],
    267: [function(e, t, r) {
        const n = e("../classes/semver")
            , s = e("../classes/range")
            , o = e("../functions/gt");
        t.exports = (e, t) => {
            e = new s(e,t);
            let r = new n("0.0.0");
            if (e.test(r))
                return r;
            if (r = new n("0.0.0-0"),
                e.test(r))
                return r;
            r = null;
            for (let t = 0; t < e.set.length; ++t) {
                const s = e.set[t];
                let i = null;
                s.forEach((e => {
                        const t = new n(e.semver.version);
                        switch (e.operator) {
                            case ">":
                                0 === t.prerelease.length ? t.patch++ : t.prerelease.push(0),
                                    t.raw = t.format();
                            case "":
                            case ">=":
                                i && !o(t, i) || (i = t);
                                break;
                            case "<":
                            case "<=":
                                break;
                            default:
                                throw new Error(`Unexpected operation: ${e.operator}`)
                        }
                    }
                )),
                !i || r && !o(r, i) || (r = i)
            }
            return r && e.test(r) ? r : null
        }
    }
        , {
            "../classes/range": 229,
            "../classes/semver": 230,
            "../functions/gt": 239
        }],
    268: [function(e, t, r) {
        const n = e("../classes/semver")
            , s = e("../classes/comparator")
            , {ANY: o} = s
            , i = e("../classes/range")
            , a = e("../functions/satisfies")
            , c = e("../functions/gt")
            , u = e("../functions/lt")
            , l = e("../functions/lte")
            , d = e("../functions/gte");
        t.exports = (e, t, r, f) => {
            let p, h, g, m, b;
            switch (e = new n(e,f),
                t = new i(t,f),
                r) {
                case ">":
                    p = c,
                        h = l,
                        g = u,
                        m = ">",
                        b = ">=";
                    break;
                case "<":
                    p = u,
                        h = d,
                        g = c,
                        m = "<",
                        b = "<=";
                    break;
                default:
                    throw new TypeError('Must provide a hilo val of "<" or ">"')
            }
            if (a(e, t, f))
                return !1;
            for (let r = 0; r < t.set.length; ++r) {
                const n = t.set[r];
                let i = null
                    , a = null;
                if (n.forEach((e => {
                        e.semver === o && (e = new s(">=0.0.0")),
                            i = i || e,
                            a = a || e,
                            p(e.semver, i.semver, f) ? i = e : g(e.semver, a.semver, f) && (a = e)
                    }
                )),
                i.operator === m || i.operator === b)
                    return !1;
                if ((!a.operator || a.operator === m) && h(e, a.semver))
                    return !1;
                if (a.operator === b && g(e, a.semver))
                    return !1
            }
            return !0
        }
    }
        , {
            "../classes/comparator": 228,
            "../classes/range": 229,
            "../classes/semver": 230,
            "../functions/gt": 239,
            "../functions/gte": 240,
            "../functions/lt": 242,
            "../functions/lte": 243,
            "../functions/satisfies": 252
        }],
    269: [function(e, t, r) {
        const n = e("../functions/satisfies.js")
            , s = e("../functions/compare.js");
        t.exports = (e, t, r) => {
            const o = [];
            let i = null
                , a = null;
            const c = e.sort(( (e, t) => s(e, t, r)));
            for (const e of c) {
                n(e, t, r) ? (a = e,
                i || (i = e)) : (a && o.push([i, a]),
                    a = null,
                    i = null)
            }
            i && o.push([i, null]);
            const u = [];
            for (const [e,t] of o)
                e === t ? u.push(e) : t || e !== c[0] ? t ? e === c[0] ? u.push(`<=${t}`) : u.push(`${e} - ${t}`) : u.push(`>=${e}`) : u.push("*");
            const l = u.join(" || ")
                , d = "string" == typeof t.raw ? t.raw : String(t);
            return l.length < d.length ? l : t
        }
    }
        , {
            "../functions/compare.js": 236,
            "../functions/satisfies.js": 252
        }],
    270: [function(e, t, r) {
        const n = e("../classes/range.js")
            , s = e("../classes/comparator.js")
            , {ANY: o} = s
            , i = e("../functions/satisfies.js")
            , a = e("../functions/compare.js")
            , c = [new s(">=0.0.0-0")]
            , u = [new s(">=0.0.0")]
            , l = (e, t, r) => {
                if (e === t)
                    return !0;
                if (1 === e.length && e[0].semver === o) {
                    if (1 === t.length && t[0].semver === o)
                        return !0;
                    e = r.includePrerelease ? c : u
                }
                if (1 === t.length && t[0].semver === o) {
                    if (r.includePrerelease)
                        return !0;
                    t = u
                }
                const n = new Set;
                let s, l, p, h, g, m, b;
                for (const t of e)
                    ">" === t.operator || ">=" === t.operator ? s = d(s, t, r) : "<" === t.operator || "<=" === t.operator ? l = f(l, t, r) : n.add(t.semver);
                if (n.size > 1)
                    return null;
                if (s && l) {
                    if (p = a(s.semver, l.semver, r),
                    p > 0)
                        return null;
                    if (0 === p && (">=" !== s.operator || "<=" !== l.operator))
                        return null
                }
                for (const e of n) {
                    if (s && !i(e, String(s), r))
                        return null;
                    if (l && !i(e, String(l), r))
                        return null;
                    for (const n of t)
                        if (!i(e, String(n), r))
                            return !1;
                    return !0
                }
                let y = !(!l || r.includePrerelease || !l.semver.prerelease.length) && l.semver
                    , w = !(!s || r.includePrerelease || !s.semver.prerelease.length) && s.semver;
                y && 1 === y.prerelease.length && "<" === l.operator && 0 === y.prerelease[0] && (y = !1);
                for (const e of t) {
                    if (b = b || ">" === e.operator || ">=" === e.operator,
                        m = m || "<" === e.operator || "<=" === e.operator,
                        s)
                        if (w && e.semver.prerelease && e.semver.prerelease.length && e.semver.major === w.major && e.semver.minor === w.minor && e.semver.patch === w.patch && (w = !1),
                        ">" === e.operator || ">=" === e.operator) {
                            if (h = d(s, e, r),
                            h === e && h !== s)
                                return !1
                        } else if (">=" === s.operator && !i(s.semver, String(e), r))
                            return !1;
                    if (l)
                        if (y && e.semver.prerelease && e.semver.prerelease.length && e.semver.major === y.major && e.semver.minor === y.minor && e.semver.patch === y.patch && (y = !1),
                        "<" === e.operator || "<=" === e.operator) {
                            if (g = f(l, e, r),
                            g === e && g !== l)
                                return !1
                        } else if ("<=" === l.operator && !i(l.semver, String(e), r))
                            return !1;
                    if (!e.operator && (l || s) && 0 !== p)
                        return !1
                }
                return !(s && m && !l && 0 !== p) && (!(l && b && !s && 0 !== p) && (!w && !y))
            }
            , d = (e, t, r) => {
                if (!e)
                    return t;
                const n = a(e.semver, t.semver, r);
                return n > 0 ? e : n < 0 || ">" === t.operator && ">=" === e.operator ? t : e
            }
            , f = (e, t, r) => {
                if (!e)
                    return t;
                const n = a(e.semver, t.semver, r);
                return n < 0 ? e : n > 0 || "<" === t.operator && "<=" === e.operator ? t : e
            }
        ;
        t.exports = (e, t, r={}) => {
            if (e === t)
                return !0;
            e = new n(e,r),
                t = new n(t,r);
            let s = !1;
            e: for (const n of e.set) {
                for (const e of t.set) {
                    const t = l(n, e, r);
                    if (s = s || null !== t,
                        t)
                        continue e
                }
                if (s)
                    return !1
            }
            return !0
        }
    }
        , {
            "../classes/comparator.js": 228,
            "../classes/range.js": 229,
            "../functions/compare.js": 236,
            "../functions/satisfies.js": 252
        }],
    271: [function(e, t, r) {
        const n = e("../classes/range");
        t.exports = (e, t) => new n(e,t).set.map((e => e.map((e => e.value)).join(" ").trim().split(" ")))
    }
        , {
            "../classes/range": 229
        }],
    272: [function(e, t, r) {
        const n = e("../classes/range");
        t.exports = (e, t) => {
            try {
                return new n(e,t).range || "*"
            } catch (e) {
                return null
            }
        }
    }
        , {
            "../classes/range": 229
        }],
    273: [function(e, t, r) {
        "use strict";
        var n = e("safe-buffer").Buffer
            , s = n.isEncoding || function(e) {
                switch ((e = "" + e) && e.toLowerCase()) {
                    case "hex":
                    case "utf8":
                    case "utf-8":
                    case "ascii":
                    case "binary":
                    case "base64":
                    case "ucs2":
                    case "ucs-2":
                    case "utf16le":
                    case "utf-16le":
                    case "raw":
                        return !0;
                    default:
                        return !1
                }
            }
        ;
        function o(e) {
            var t;
            switch (this.encoding = function(e) {
                var t = function(e) {
                    if (!e)
                        return "utf8";
                    for (var t; ; )
                        switch (e) {
                            case "utf8":
                            case "utf-8":
                                return "utf8";
                            case "ucs2":
                            case "ucs-2":
                            case "utf16le":
                            case "utf-16le":
                                return "utf16le";
                            case "latin1":
                            case "binary":
                                return "latin1";
                            case "base64":
                            case "ascii":
                            case "hex":
                                return e;
                            default:
                                if (t)
                                    return;
                                e = ("" + e).toLowerCase(),
                                    t = !0
                        }
                }(e);
                if ("string" != typeof t && (n.isEncoding === s || !s(e)))
                    throw new Error("Unknown encoding: " + e);
                return t || e
            }(e),
                this.encoding) {
                case "utf16le":
                    this.text = c,
                        this.end = u,
                        t = 4;
                    break;
                case "utf8":
                    this.fillLast = a,
                        t = 4;
                    break;
                case "base64":
                    this.text = l,
                        this.end = d,
                        t = 3;
                    break;
                default:
                    return this.write = f,
                        void (this.end = p)
            }
            this.lastNeed = 0,
                this.lastTotal = 0,
                this.lastChar = n.allocUnsafe(t)
        }
        function i(e) {
            return e <= 127 ? 0 : e >> 5 == 6 ? 2 : e >> 4 == 14 ? 3 : e >> 3 == 30 ? 4 : e >> 6 == 2 ? -1 : -2
        }
        function a(e) {
            var t = this.lastTotal - this.lastNeed
                , r = function(e, t, r) {
                if (128 != (192 & t[0]))
                    return e.lastNeed = 0,
                        "�";
                if (e.lastNeed > 1 && t.length > 1) {
                    if (128 != (192 & t[1]))
                        return e.lastNeed = 1,
                            "�";
                    if (e.lastNeed > 2 && t.length > 2 && 128 != (192 & t[2]))
                        return e.lastNeed = 2,
                            "�"
                }
            }(this, e);
            return void 0 !== r ? r : this.lastNeed <= e.length ? (e.copy(this.lastChar, t, 0, this.lastNeed),
                this.lastChar.toString(this.encoding, 0, this.lastTotal)) : (e.copy(this.lastChar, t, 0, e.length),
                void (this.lastNeed -= e.length))
        }
        function c(e, t) {
            if ((e.length - t) % 2 == 0) {
                var r = e.toString("utf16le", t);
                if (r) {
                    var n = r.charCodeAt(r.length - 1);
                    if (n >= 55296 && n <= 56319)
                        return this.lastNeed = 2,
                            this.lastTotal = 4,
                            this.lastChar[0] = e[e.length - 2],
                            this.lastChar[1] = e[e.length - 1],
                            r.slice(0, -1)
                }
                return r
            }
            return this.lastNeed = 1,
                this.lastTotal = 2,
                this.lastChar[0] = e[e.length - 1],
                e.toString("utf16le", t, e.length - 1)
        }
        function u(e) {
            var t = e && e.length ? this.write(e) : "";
            if (this.lastNeed) {
                var r = this.lastTotal - this.lastNeed;
                return t + this.lastChar.toString("utf16le", 0, r)
            }
            return t
        }
        function l(e, t) {
            var r = (e.length - t) % 3;
            return 0 === r ? e.toString("base64", t) : (this.lastNeed = 3 - r,
                this.lastTotal = 3,
                1 === r ? this.lastChar[0] = e[e.length - 1] : (this.lastChar[0] = e[e.length - 2],
                    this.lastChar[1] = e[e.length - 1]),
                e.toString("base64", t, e.length - r))
        }
        function d(e) {
            var t = e && e.length ? this.write(e) : "";
            return this.lastNeed ? t + this.lastChar.toString("base64", 0, 3 - this.lastNeed) : t
        }
        function f(e) {
            return e.toString(this.encoding)
        }
        function p(e) {
            return e && e.length ? this.write(e) : ""
        }
        r.StringDecoder = o,
            o.prototype.write = function(e) {
                if (0 === e.length)
                    return "";
                var t, r;
                if (this.lastNeed) {
                    if (void 0 === (t = this.fillLast(e)))
                        return "";
                    r = this.lastNeed,
                        this.lastNeed = 0
                } else
                    r = 0;
                return r < e.length ? t ? t + this.text(e, r) : this.text(e, r) : t || ""
            }
            ,
            o.prototype.end = function(e) {
                var t = e && e.length ? this.write(e) : "";
                return this.lastNeed ? t + "�" : t
            }
            ,
            o.prototype.text = function(e, t) {
                var r = function(e, t, r) {
                    var n = t.length - 1;
                    if (n < r)
                        return 0;
                    var s = i(t[n]);
                    if (s >= 0)
                        return s > 0 && (e.lastNeed = s - 1),
                            s;
                    if (--n < r || -2 === s)
                        return 0;
                    if (s = i(t[n]),
                    s >= 0)
                        return s > 0 && (e.lastNeed = s - 2),
                            s;
                    if (--n < r || -2 === s)
                        return 0;
                    if (s = i(t[n]),
                    s >= 0)
                        return s > 0 && (2 === s ? s = 0 : e.lastNeed = s - 3),
                            s;
                    return 0
                }(this, e, t);
                if (!this.lastNeed)
                    return e.toString("utf8", t);
                this.lastTotal = r;
                var n = e.length - (r - this.lastNeed);
                return e.copy(this.lastChar, 0, n),
                    e.toString("utf8", t, n)
            }
            ,
            o.prototype.fillLast = function(e) {
                if (this.lastNeed <= e.length)
                    return e.copy(this.lastChar, this.lastTotal - this.lastNeed, 0, this.lastNeed),
                        this.lastChar.toString(this.encoding, 0, this.lastTotal);
                e.copy(this.lastChar, this.lastTotal - this.lastNeed, 0, e.length),
                    this.lastNeed -= e.length
            }
    }
        , {
            "safe-buffer": 227
        }],
    274: [function(e, t, r) {
        (function(e) {
                (function() {
                        function r(t) {
                            try {
                                if (!e.localStorage)
                                    return !1
                            } catch (e) {
                                return !1
                            }
                            var r = e.localStorage[t];
                            return null != r && "true" === String(r).toLowerCase()
                        }
                        t.exports = function(e, t) {
                            if (r("noDeprecation"))
                                return e;
                            var n = !1;
                            return function() {
                                if (!n) {
                                    if (r("throwDeprecation"))
                                        throw new Error(t);
                                    r("traceDeprecation") ? console.trace(t) : console.warn(t),
                                        n = !0
                                }
                                return e.apply(this, arguments)
                            }
                        }
                    }
                ).call(this)
            }
        ).call(this, "undefined" != typeof global ? global : "undefined" != typeof self ? self : "undefined" != typeof window ? window : {})
    }
        , {}],
    275: [function(e, t, r) {
        "use strict";
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            Object.defineProperty(r, "v1", {
                enumerable: !0,
                get: function() {
                    return n.default
                }
            }),
            Object.defineProperty(r, "v3", {
                enumerable: !0,
                get: function() {
                    return s.default
                }
            }),
            Object.defineProperty(r, "v4", {
                enumerable: !0,
                get: function() {
                    return o.default
                }
            }),
            Object.defineProperty(r, "v5", {
                enumerable: !0,
                get: function() {
                    return i.default
                }
            }),
            Object.defineProperty(r, "NIL", {
                enumerable: !0,
                get: function() {
                    return a.default
                }
            }),
            Object.defineProperty(r, "version", {
                enumerable: !0,
                get: function() {
                    return c.default
                }
            }),
            Object.defineProperty(r, "validate", {
                enumerable: !0,
                get: function() {
                    return u.default
                }
            }),
            Object.defineProperty(r, "stringify", {
                enumerable: !0,
                get: function() {
                    return l.default
                }
            }),
            Object.defineProperty(r, "parse", {
                enumerable: !0,
                get: function() {
                    return d.default
                }
            });
        var n = f(e("./v1.js"))
            , s = f(e("./v3.js"))
            , o = f(e("./v4.js"))
            , i = f(e("./v5.js"))
            , a = f(e("./nil.js"))
            , c = f(e("./version.js"))
            , u = f(e("./validate.js"))
            , l = f(e("./stringify.js"))
            , d = f(e("./parse.js"));
        function f(e) {
            return e && e.__esModule ? e : {
                default: e
            }
        }
    }
        , {
            "./nil.js": 277,
            "./parse.js": 278,
            "./stringify.js": 282,
            "./v1.js": 283,
            "./v3.js": 284,
            "./v4.js": 286,
            "./v5.js": 287,
            "./validate.js": 288,
            "./version.js": 289
        }],
    276: [function(e, t, r) {
        "use strict";
        function n(e) {
            return 14 + (e + 64 >>> 9 << 4) + 1
        }
        function s(e, t) {
            const r = (65535 & e) + (65535 & t);
            return (e >> 16) + (t >> 16) + (r >> 16) << 16 | 65535 & r
        }
        function o(e, t, r, n, o, i) {
            return s((a = s(s(t, e), s(n, i))) << (c = o) | a >>> 32 - c, r);
            var a, c
        }
        function i(e, t, r, n, s, i, a) {
            return o(t & r | ~t & n, e, t, s, i, a)
        }
        function a(e, t, r, n, s, i, a) {
            return o(t & n | r & ~n, e, t, s, i, a)
        }
        function c(e, t, r, n, s, i, a) {
            return o(t ^ r ^ n, e, t, s, i, a)
        }
        function u(e, t, r, n, s, i, a) {
            return o(r ^ (t | ~n), e, t, s, i, a)
        }
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.default = void 0;
        var l = function(e) {
            if ("string" == typeof e) {
                const t = unescape(encodeURIComponent(e));
                e = new Uint8Array(t.length);
                for (let r = 0; r < t.length; ++r)
                    e[r] = t.charCodeAt(r)
            }
            return function(e) {
                const t = []
                    , r = 32 * e.length
                    , n = "0123456789abcdef";
                for (let s = 0; s < r; s += 8) {
                    const r = e[s >> 5] >>> s % 32 & 255
                        , o = parseInt(n.charAt(r >>> 4 & 15) + n.charAt(15 & r), 16);
                    t.push(o)
                }
                return t
            }(function(e, t) {
                e[t >> 5] |= 128 << t % 32,
                    e[n(t) - 1] = t;
                let r = 1732584193
                    , o = -271733879
                    , l = -1732584194
                    , d = 271733878;
                for (let t = 0; t < e.length; t += 16) {
                    const n = r
                        , f = o
                        , p = l
                        , h = d;
                    r = i(r, o, l, d, e[t], 7, -680876936),
                        d = i(d, r, o, l, e[t + 1], 12, -389564586),
                        l = i(l, d, r, o, e[t + 2], 17, 606105819),
                        o = i(o, l, d, r, e[t + 3], 22, -1044525330),
                        r = i(r, o, l, d, e[t + 4], 7, -176418897),
                        d = i(d, r, o, l, e[t + 5], 12, 1200080426),
                        l = i(l, d, r, o, e[t + 6], 17, -1473231341),
                        o = i(o, l, d, r, e[t + 7], 22, -45705983),
                        r = i(r, o, l, d, e[t + 8], 7, 1770035416),
                        d = i(d, r, o, l, e[t + 9], 12, -1958414417),
                        l = i(l, d, r, o, e[t + 10], 17, -42063),
                        o = i(o, l, d, r, e[t + 11], 22, -1990404162),
                        r = i(r, o, l, d, e[t + 12], 7, 1804603682),
                        d = i(d, r, o, l, e[t + 13], 12, -40341101),
                        l = i(l, d, r, o, e[t + 14], 17, -1502002290),
                        o = i(o, l, d, r, e[t + 15], 22, 1236535329),
                        r = a(r, o, l, d, e[t + 1], 5, -165796510),
                        d = a(d, r, o, l, e[t + 6], 9, -1069501632),
                        l = a(l, d, r, o, e[t + 11], 14, 643717713),
                        o = a(o, l, d, r, e[t], 20, -373897302),
                        r = a(r, o, l, d, e[t + 5], 5, -701558691),
                        d = a(d, r, o, l, e[t + 10], 9, 38016083),
                        l = a(l, d, r, o, e[t + 15], 14, -660478335),
                        o = a(o, l, d, r, e[t + 4], 20, -405537848),
                        r = a(r, o, l, d, e[t + 9], 5, 568446438),
                        d = a(d, r, o, l, e[t + 14], 9, -1019803690),
                        l = a(l, d, r, o, e[t + 3], 14, -187363961),
                        o = a(o, l, d, r, e[t + 8], 20, 1163531501),
                        r = a(r, o, l, d, e[t + 13], 5, -1444681467),
                        d = a(d, r, o, l, e[t + 2], 9, -51403784),
                        l = a(l, d, r, o, e[t + 7], 14, 1735328473),
                        o = a(o, l, d, r, e[t + 12], 20, -1926607734),
                        r = c(r, o, l, d, e[t + 5], 4, -378558),
                        d = c(d, r, o, l, e[t + 8], 11, -2022574463),
                        l = c(l, d, r, o, e[t + 11], 16, 1839030562),
                        o = c(o, l, d, r, e[t + 14], 23, -35309556),
                        r = c(r, o, l, d, e[t + 1], 4, -1530992060),
                        d = c(d, r, o, l, e[t + 4], 11, 1272893353),
                        l = c(l, d, r, o, e[t + 7], 16, -155497632),
                        o = c(o, l, d, r, e[t + 10], 23, -1094730640),
                        r = c(r, o, l, d, e[t + 13], 4, 681279174),
                        d = c(d, r, o, l, e[t], 11, -358537222),
                        l = c(l, d, r, o, e[t + 3], 16, -722521979),
                        o = c(o, l, d, r, e[t + 6], 23, 76029189),
                        r = c(r, o, l, d, e[t + 9], 4, -640364487),
                        d = c(d, r, o, l, e[t + 12], 11, -421815835),
                        l = c(l, d, r, o, e[t + 15], 16, 530742520),
                        o = c(o, l, d, r, e[t + 2], 23, -995338651),
                        r = u(r, o, l, d, e[t], 6, -198630844),
                        d = u(d, r, o, l, e[t + 7], 10, 1126891415),
                        l = u(l, d, r, o, e[t + 14], 15, -1416354905),
                        o = u(o, l, d, r, e[t + 5], 21, -57434055),
                        r = u(r, o, l, d, e[t + 12], 6, 1700485571),
                        d = u(d, r, o, l, e[t + 3], 10, -1894986606),
                        l = u(l, d, r, o, e[t + 10], 15, -1051523),
                        o = u(o, l, d, r, e[t + 1], 21, -2054922799),
                        r = u(r, o, l, d, e[t + 8], 6, 1873313359),
                        d = u(d, r, o, l, e[t + 15], 10, -30611744),
                        l = u(l, d, r, o, e[t + 6], 15, -1560198380),
                        o = u(o, l, d, r, e[t + 13], 21, 1309151649),
                        r = u(r, o, l, d, e[t + 4], 6, -145523070),
                        d = u(d, r, o, l, e[t + 11], 10, -1120210379),
                        l = u(l, d, r, o, e[t + 2], 15, 718787259),
                        o = u(o, l, d, r, e[t + 9], 21, -343485551),
                        r = s(r, n),
                        o = s(o, f),
                        l = s(l, p),
                        d = s(d, h)
                }
                return [r, o, l, d]
            }(function(e) {
                if (0 === e.length)
                    return [];
                const t = 8 * e.length
                    , r = new Uint32Array(n(t));
                for (let n = 0; n < t; n += 8)
                    r[n >> 5] |= (255 & e[n / 8]) << n % 32;
                return r
            }(e), 8 * e.length))
        };
        r.default = l
    }
        , {}],
    277: [function(e, t, r) {
        "use strict";
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.default = void 0;
        r.default = "00000000-0000-0000-0000-000000000000"
    }
        , {}],
    278: [function(e, t, r) {
        "use strict";
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.default = void 0;
        var n, s = (n = e("./validate.js")) && n.__esModule ? n : {
            default: n
        };
        var o = function(e) {
            if (!(0,
                s.default)(e))
                throw TypeError("Invalid UUID");
            let t;
            const r = new Uint8Array(16);
            return r[0] = (t = parseInt(e.slice(0, 8), 16)) >>> 24,
                r[1] = t >>> 16 & 255,
                r[2] = t >>> 8 & 255,
                r[3] = 255 & t,
                r[4] = (t = parseInt(e.slice(9, 13), 16)) >>> 8,
                r[5] = 255 & t,
                r[6] = (t = parseInt(e.slice(14, 18), 16)) >>> 8,
                r[7] = 255 & t,
                r[8] = (t = parseInt(e.slice(19, 23), 16)) >>> 8,
                r[9] = 255 & t,
                r[10] = (t = parseInt(e.slice(24, 36), 16)) / 1099511627776 & 255,
                r[11] = t / 4294967296 & 255,
                r[12] = t >>> 24 & 255,
                r[13] = t >>> 16 & 255,
                r[14] = t >>> 8 & 255,
                r[15] = 255 & t,
                r
        };
        r.default = o
    }
        , {
            "./validate.js": 288
        }],
    279: [function(e, t, r) {
        "use strict";
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.default = void 0;
        r.default = /^(?:[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|00000000-0000-0000-0000-000000000000)$/i
    }
        , {}],
    280: [function(e, t, r) {
        "use strict";
        let n;
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.default = function() {
                if (!n && (n = "undefined" != typeof crypto && crypto.getRandomValues && crypto.getRandomValues.bind(crypto) || "undefined" != typeof msCrypto && "function" == typeof msCrypto.getRandomValues && msCrypto.getRandomValues.bind(msCrypto),
                    !n))
                    throw new Error("crypto.getRandomValues() not supported. See https://github.com/uuidjs/uuid#getrandomvalues-not-supported");
                return n(s)
            }
        ;
        const s = new Uint8Array(16)
    }
        , {}],
    281: [function(e, t, r) {
        "use strict";
        function n(e, t, r, n) {
            switch (e) {
                case 0:
                    return t & r ^ ~t & n;
                case 1:
                case 3:
                    return t ^ r ^ n;
                case 2:
                    return t & r ^ t & n ^ r & n
            }
        }
        function s(e, t) {
            return e << t | e >>> 32 - t
        }
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.default = void 0;
        var o = function(e) {
            const t = [1518500249, 1859775393, 2400959708, 3395469782]
                , r = [1732584193, 4023233417, 2562383102, 271733878, 3285377520];
            if ("string" == typeof e) {
                const t = unescape(encodeURIComponent(e));
                e = [];
                for (let r = 0; r < t.length; ++r)
                    e.push(t.charCodeAt(r))
            } else
                Array.isArray(e) || (e = Array.prototype.slice.call(e));
            e.push(128);
            const o = e.length / 4 + 2
                , i = Math.ceil(o / 16)
                , a = new Array(i);
            for (let t = 0; t < i; ++t) {
                const r = new Uint32Array(16);
                for (let n = 0; n < 16; ++n)
                    r[n] = e[64 * t + 4 * n] << 24 | e[64 * t + 4 * n + 1] << 16 | e[64 * t + 4 * n + 2] << 8 | e[64 * t + 4 * n + 3];
                a[t] = r
            }
            a[i - 1][14] = 8 * (e.length - 1) / Math.pow(2, 32),
                a[i - 1][14] = Math.floor(a[i - 1][14]),
                a[i - 1][15] = 8 * (e.length - 1) & 4294967295;
            for (let e = 0; e < i; ++e) {
                const o = new Uint32Array(80);
                for (let t = 0; t < 16; ++t)
                    o[t] = a[e][t];
                for (let e = 16; e < 80; ++e)
                    o[e] = s(o[e - 3] ^ o[e - 8] ^ o[e - 14] ^ o[e - 16], 1);
                let i = r[0]
                    , c = r[1]
                    , u = r[2]
                    , l = r[3]
                    , d = r[4];
                for (let e = 0; e < 80; ++e) {
                    const r = Math.floor(e / 20)
                        , a = s(i, 5) + n(r, c, u, l) + d + t[r] + o[e] >>> 0;
                    d = l,
                        l = u,
                        u = s(c, 30) >>> 0,
                        c = i,
                        i = a
                }
                r[0] = r[0] + i >>> 0,
                    r[1] = r[1] + c >>> 0,
                    r[2] = r[2] + u >>> 0,
                    r[3] = r[3] + l >>> 0,
                    r[4] = r[4] + d >>> 0
            }
            return [r[0] >> 24 & 255, r[0] >> 16 & 255, r[0] >> 8 & 255, 255 & r[0], r[1] >> 24 & 255, r[1] >> 16 & 255, r[1] >> 8 & 255, 255 & r[1], r[2] >> 24 & 255, r[2] >> 16 & 255, r[2] >> 8 & 255, 255 & r[2], r[3] >> 24 & 255, r[3] >> 16 & 255, r[3] >> 8 & 255, 255 & r[3], r[4] >> 24 & 255, r[4] >> 16 & 255, r[4] >> 8 & 255, 255 & r[4]]
        };
        r.default = o
    }
        , {}],
    282: [function(e, t, r) {
        "use strict";
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.default = void 0;
        var n, s = (n = e("./validate.js")) && n.__esModule ? n : {
            default: n
        };
        const o = [];
        for (let e = 0; e < 256; ++e)
            o.push((e + 256).toString(16).substr(1));
        var i = function(e, t=0) {
            const r = (o[e[t + 0]] + o[e[t + 1]] + o[e[t + 2]] + o[e[t + 3]] + "-" + o[e[t + 4]] + o[e[t + 5]] + "-" + o[e[t + 6]] + o[e[t + 7]] + "-" + o[e[t + 8]] + o[e[t + 9]] + "-" + o[e[t + 10]] + o[e[t + 11]] + o[e[t + 12]] + o[e[t + 13]] + o[e[t + 14]] + o[e[t + 15]]).toLowerCase();
            if (!(0,
                s.default)(r))
                throw TypeError("Stringified UUID is invalid");
            return r
        };
        r.default = i
    }
        , {
            "./validate.js": 288
        }],
    283: [function(e, t, r) {
        "use strict";
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.default = void 0;
        var n = o(e("./rng.js"))
            , s = o(e("./stringify.js"));
        function o(e) {
            return e && e.__esModule ? e : {
                default: e
            }
        }
        let i, a, c = 0, u = 0;
        var l = function(e, t, r) {
            let o = t && r || 0;
            const l = t || new Array(16);
            let d = (e = e || {}).node || i
                , f = void 0 !== e.clockseq ? e.clockseq : a;
            if (null == d || null == f) {
                const t = e.random || (e.rng || n.default)();
                null == d && (d = i = [1 | t[0], t[1], t[2], t[3], t[4], t[5]]),
                null == f && (f = a = 16383 & (t[6] << 8 | t[7]))
            }
            let p = void 0 !== e.msecs ? e.msecs : Date.now()
                , h = void 0 !== e.nsecs ? e.nsecs : u + 1;
            const g = p - c + (h - u) / 1e4;
            if (g < 0 && void 0 === e.clockseq && (f = f + 1 & 16383),
            (g < 0 || p > c) && void 0 === e.nsecs && (h = 0),
            h >= 1e4)
                throw new Error("uuid.v1(): Can't create more than 10M uuids/sec");
            c = p,
                u = h,
                a = f,
                p += 122192928e5;
            const m = (1e4 * (268435455 & p) + h) % 4294967296;
            l[o++] = m >>> 24 & 255,
                l[o++] = m >>> 16 & 255,
                l[o++] = m >>> 8 & 255,
                l[o++] = 255 & m;
            const b = p / 4294967296 * 1e4 & 268435455;
            l[o++] = b >>> 8 & 255,
                l[o++] = 255 & b,
                l[o++] = b >>> 24 & 15 | 16,
                l[o++] = b >>> 16 & 255,
                l[o++] = f >>> 8 | 128,
                l[o++] = 255 & f;
            for (let e = 0; e < 6; ++e)
                l[o + e] = d[e];
            return t || (0,
                s.default)(l)
        };
        r.default = l
    }
        , {
            "./rng.js": 280,
            "./stringify.js": 282
        }],
    284: [function(e, t, r) {
        "use strict";
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.default = void 0;
        var n = o(e("./v35.js"))
            , s = o(e("./md5.js"));
        function o(e) {
            return e && e.__esModule ? e : {
                default: e
            }
        }
        var i = (0,
            n.default)("v3", 48, s.default);
        r.default = i
    }
        , {
            "./md5.js": 276,
            "./v35.js": 285
        }],
    285: [function(e, t, r) {
        "use strict";
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.default = function(e, t, r) {
                function o(e, o, i, a) {
                    if ("string" == typeof e && (e = function(e) {
                        e = unescape(encodeURIComponent(e));
                        const t = [];
                        for (let r = 0; r < e.length; ++r)
                            t.push(e.charCodeAt(r));
                        return t
                    }(e)),
                    "string" == typeof o && (o = (0,
                        s.default)(o)),
                    16 !== o.length)
                        throw TypeError("Namespace must be array-like (16 iterable integer values, 0-255)");
                    let c = new Uint8Array(16 + e.length);
                    if (c.set(o),
                        c.set(e, o.length),
                        c = r(c),
                        c[6] = 15 & c[6] | t,
                        c[8] = 63 & c[8] | 128,
                        i) {
                        a = a || 0;
                        for (let e = 0; e < 16; ++e)
                            i[a + e] = c[e];
                        return i
                    }
                    return (0,
                        n.default)(c)
                }
                try {
                    o.name = e
                } catch (e) {}
                return o.DNS = i,
                    o.URL = a,
                    o
            }
            ,
            r.URL = r.DNS = void 0;
        var n = o(e("./stringify.js"))
            , s = o(e("./parse.js"));
        function o(e) {
            return e && e.__esModule ? e : {
                default: e
            }
        }
        const i = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
        r.DNS = i;
        const a = "6ba7b811-9dad-11d1-80b4-00c04fd430c8";
        r.URL = a
    }
        , {
            "./parse.js": 278,
            "./stringify.js": 282
        }],
    286: [function(e, t, r) {
        "use strict";
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.default = void 0;
        var n = o(e("./rng.js"))
            , s = o(e("./stringify.js"));
        function o(e) {
            return e && e.__esModule ? e : {
                default: e
            }
        }
        var i = function(e, t, r) {
            const o = (e = e || {}).random || (e.rng || n.default)();
            if (o[6] = 15 & o[6] | 64,
                o[8] = 63 & o[8] | 128,
                t) {
                r = r || 0;
                for (let e = 0; e < 16; ++e)
                    t[r + e] = o[e];
                return t
            }
            return (0,
                s.default)(o)
        };
        r.default = i
    }
        , {
            "./rng.js": 280,
            "./stringify.js": 282
        }],
    287: [function(e, t, r) {
        "use strict";
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.default = void 0;
        var n = o(e("./v35.js"))
            , s = o(e("./sha1.js"));
        function o(e) {
            return e && e.__esModule ? e : {
                default: e
            }
        }
        var i = (0,
            n.default)("v5", 80, s.default);
        r.default = i
    }
        , {
            "./sha1.js": 281,
            "./v35.js": 285
        }],
    288: [function(e, t, r) {
        "use strict";
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.default = void 0;
        var n, s = (n = e("./regex.js")) && n.__esModule ? n : {
            default: n
        };
        var o = function(e) {
            return "string" == typeof e && s.default.test(e)
        };
        r.default = o
    }
        , {
            "./regex.js": 279
        }],
    289: [function(e, t, r) {
        "use strict";
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.default = void 0;
        var n, s = (n = e("./validate.js")) && n.__esModule ? n : {
            default: n
        };
        var o = function(e) {
            if (!(0,
                s.default)(e))
                throw TypeError("Invalid UUID");
            return parseInt(e.substr(14, 1), 16)
        };
        r.default = o
    }
        , {
            "./validate.js": 288
        }],
    290: [function(e, t, r) {
        t.exports = function e(t, r) {
            if (t && r)
                return e(t)(r);
            if ("function" != typeof t)
                throw new TypeError("need wrapper function");
            return Object.keys(t).forEach((function(e) {
                    n[e] = t[e]
                }
            )),
                n;
            function n() {
                for (var e = new Array(arguments.length), r = 0; r < e.length; r++)
                    e[r] = arguments[r];
                var n = t.apply(this, e)
                    , s = e[e.length - 1];
                return "function" == typeof n && n !== s && Object.keys(s).forEach((function(e) {
                        n[e] = s[e]
                    }
                )),
                    n
            }
        }
    }
        , {}],
    291: [function(e, t, r) {
        "use strict";
        function n(e) {
            return function({pathname: e}) {
                const t = [/\.xml$/u, /\.pdf$/u];
                for (let r = 0; r < t.length; r++)
                    if (t[r].test(e))
                        return !1;
                return !0
            }(e) && !function(e) {
                const t = ["execution.consensys.io", "execution.metamask.io", "uscourts.gov", "dropbox.com", "webbyawards.com", "adyen.com", "gravityforms.com", "harbourair.com", "ani.gamer.com.tw", "blueskybooking.com", "sharefile.com", "battle.net"]
                    , r = ["cdn.shopify.com/s/javascripts/tricorder/xtld-read-only-frame.html"]
                    , {hostname: n, pathname: s} = e
                    , o = e => e.endsWith("/") ? e.slice(0, -1) : e;
                return t.some((e => e === n || n.endsWith(`.${e}`))) || r.some((e => o(e) === o(n + s)))
            }(e)
        }
        function s() {
            return function() {
                const {doctype: e} = window.document;
                if (e)
                    return "html" === e.name;
                return !0
            }() && function() {
                const e = document.documentElement.nodeName;
                if (e)
                    return "html" === e.toLowerCase();
                return !0
            }()
        }
        Object.defineProperty(r, "__esModule", {
            value: !0
        }),
            r.checkDocumentForProviderInjection = s,
            r.checkURLForProviderInjection = n,
            r.default = function() {
                return n(new URL(window.location)) && s()
            }
    }
        , {}]
}, {}, [1]);
