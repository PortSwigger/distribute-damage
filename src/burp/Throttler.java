package burp;

import java.util.Date;
import java.util.HashMap;
import java.util.concurrent.locks.Lock;

class Throttler implements IHttpListener {
    private HashMap<String, Long> locks = new HashMap<>();
    String instanceCacheBust;

    Throttler() {
        instanceCacheBust = Utilities.generateCanary();
    }

    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        Lock spiderLock = null;
        if (toolFlag == IBurpExtenderCallbacks.TOOL_SPIDER) {
            spiderLock = Utilities.spiderLock.readLock();
            spiderLock.lock();
        }
        try {
            if(messageIsRequest) {
                addCacheBuster(messageInfo);
            }

            if (messageIsRequest && Utilities.THROTTLED_COMPONENTS.contains(toolFlag)) {
                String hostname = messageInfo.getHttpService().getHost();
                delayRequest(hostname);
            }
        }
        finally {
            if (spiderLock != null) {
                spiderLock.unlock();
            }
        }

    }

    private void addCacheBuster(IHttpRequestResponse messageInfo) {
        IParameter cacheBuster = burp.Utilities.helpers.buildParameter(instanceCacheBust, "1", IParameter.PARAM_URL);
        messageInfo.setRequest(Utilities.helpers.addParameter(messageInfo.getRequest(), cacheBuster));
    }


    public void delayRequest(String hostname){
        if (hostname.equals("bwapps") || hostname.equals("labs-linux")) {
            return;
        }

        synchronized(hostname.intern()) {
            if (locks.containsKey(hostname)) {
                long waitFor = Utilities.throttle - (new Date().getTime() - locks.get(hostname));
                if (waitFor > 0) {
                    try {
                        Thread.sleep(waitFor);
                    } catch (java.lang.InterruptedException e) {
                        Utilities.err("Interrupted while sleeping");
                    }
                }
            }
            locks.put(hostname, new Date().getTime());
        }
    }
}
