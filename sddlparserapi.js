function createDeferral() {
    const deferral = { };
    deferral.promise = new Promise((resolve, reject) => {
        deferral.resolve = resolve;
        deferral.reject = reject;
    });
    return deferral;
}

window.parseSddlAsync = (() => {
    let parseCount = 0;
    let worker;
    function ensureWorker() {
        if (!worker) {
            worker = new Worker("sddlparserworker.js");
        }
        return worker;
    }

    function parseSddlAsync(sddlToParse) {
        const deferral = createDeferral();
        const worker = ensureWorker();
        const parseIndex = parseCount++;

        worker.onmessage = (msg) => {
            if (msg.data.parseIndex === parseIndex) {
                if (msg.data.resolve) {
                    deferral.resolve(msg.data.result);
                }
                else {
                    deferral.reject(msg.data.result);
                }
            }
        };
        worker.postMessage({
            sddlToParse,
            parseIndex
        });

        return deferral.promise;
    }

    return parseSddlAsync;
})();