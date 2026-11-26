/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.apache.coyote.http2;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.concurrent.atomic.AtomicInteger;

import jakarta.servlet.AsyncContext;
import jakarta.servlet.AsyncEvent;
import jakarta.servlet.AsyncListener;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.junit.Assert;
import org.junit.Test;

import org.apache.catalina.Context;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.Wrapper;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.startup.Tomcat;
import org.apache.coyote.Request;
import org.apache.coyote.http11.AbstractHttp11Protocol;

/**
 * Tests that the request and response associated with a Stream are only returned to the pool for re-use if the Stream
 * completed cleanly. If the Stream ended with an error that prevents further I/O or with an asynchronous timeout, an
 * application thread may still be using the request and/or response. Re-using them in that case could result in the
 * remaining data being written to a different stream, possibly on a different connection.
 */
public class TestHttp2RequestAndResponseReuse extends Http2TestBase {

    private static final String TIMEOUT_BODY = "TIMEOUT";

    /*
     * Re-use, if it happens, takes place as soon as the StreamProcessor finishes processing the stream so this is a
     * generous upper bound.
     */
    private static final int NO_REUSE_WAIT_MILLIS = 2000;


    @Test
    public void testReuseAfterCleanStream() throws Exception {
        http2Connect();

        ReuseTrackingHttp2Protocol protocol = (ReuseTrackingHttp2Protocol) http2Protocol;

        sendSimpleGetRequest(3);
        readSimpleGetResponse();
        Assert.assertEquals(getSimpleResponseTrace(3), output.getTrace());

        // The stream completed cleanly so the request and response should be returned to the pool exactly once
        int count = 0;
        while (protocol.getLastPoppedPushCount() == 0 && count < 100) {
            Thread.sleep(50);
            count++;
        }
        Assert.assertEquals(1, protocol.getLastPoppedPushCount());
    }


    /*
     * The application thread is blocked writing the response (empty flow control window) when the stream write
     * timeout fires. The resulting error prevents further I/O for the stream so the request and response must not be
     * re-used.
     */
    @Test
    public void testNoReuseAfterStreamError() throws Exception {
        http2Connect();

        ReuseTrackingHttp2Protocol protocol = (ReuseTrackingHttp2Protocol) http2Protocol;

        sendSettings(0, false, new SettingValue(Setting.INITIAL_WINDOW_SIZE.getId(), 0));

        byte[] frameHeader = new byte[9];
        ByteBuffer headersPayload = ByteBuffer.allocate(128);
        buildGetRequest(frameHeader, headersPayload, null, 3, "/blockedwrite");
        writeFrame(frameHeader, headersPayload);

        // Settings ack, headers and then the reset once the stream write timeout fires
        readFramesUntil("3-RST-");
        String trace = output.getTrace();
        Assert.assertTrue(trace, trace.contains("3-RST-[11]\n"));

        assertNotReused(protocol, 5);
    }


    /*
     * The asynchronous request times out. The request and response must not be re-used even though the
     * AsyncListener completed the request cleanly.
     */
    @Test
    public void testNoReuseAfterAsyncTimeout() throws Exception {
        http2Connect();

        ReuseTrackingHttp2Protocol protocol = (ReuseTrackingHttp2Protocol) http2Protocol;

        output.setTraceBody(true);

        byte[] frameHeader = new byte[9];
        ByteBuffer headersPayload = ByteBuffer.allocate(128);
        buildGetRequest(frameHeader, headersPayload, null, 3, "/asynctimeout");
        writeFrame(frameHeader, headersPayload);

        readFramesUntil("3-EndOfStream");
        String trace = output.getTrace();
        Assert.assertTrue(trace, trace.contains("3-Body-" + TIMEOUT_BODY + "\n"));

        assertNotReused(protocol, 5);
    }


    private void assertNotReused(ReuseTrackingHttp2Protocol protocol, int nextStreamId) throws Exception {
        Request failedStreamRequest = protocol.getLastPopped();
        Assert.assertNotNull(failedStreamRequest);

        int count = 0;
        while (protocol.getLastPoppedPushCount() == 0 && count < NO_REUSE_WAIT_MILLIS / 50) {
            Thread.sleep(50);
            count++;
        }
        Assert.assertEquals(0, protocol.getLastPoppedPushCount());

        // A new stream must not be given the request and response that were associated with the previous stream
        output.clearTrace();
        byte[] frameHeader = new byte[9];
        ByteBuffer headersPayload = ByteBuffer.allocate(128);
        buildGetRequest(frameHeader, headersPayload, null, nextStreamId, "/nocontent");
        writeFrame(frameHeader, headersPayload);

        readFramesUntil(nextStreamId + "-EndOfStream");
        String trace = output.getTrace();
        Assert.assertTrue(trace, trace.contains(nextStreamId + "-Header-[:status]-[204]\n"));

        Assert.assertNotSame(failedStreamRequest, protocol.getLastPopped());
    }


    private void readFramesUntil(String marker) throws Exception {
        int frames = 0;
        while (!output.getTrace().contains(marker) && frames < 20) {
            parser.readFrame();
            frames++;
        }
    }


    @Override
    protected void enableHttp2(long maxConcurrentStreams, boolean tls, long readTimeout, long writeTimeout,
            long keepAliveTimeout, long streamReadTimout, long streamWriteTimeout) {
        Tomcat tomcat = getTomcatInstance();
        Connector connector = tomcat.getConnector();
        Assert.assertTrue(connector.setProperty("useAsyncIO", Boolean.toString(useAsyncIO)));
        http2Protocol = new ReuseTrackingHttp2Protocol();
        http2Protocol.setReadTimeout(readTimeout);
        http2Protocol.setWriteTimeout(writeTimeout);
        http2Protocol.setKeepAliveTimeout(keepAliveTimeout);
        http2Protocol.setStreamReadTimeout(streamReadTimout);
        http2Protocol.setStreamWriteTimeout(streamWriteTimeout);
        http2Protocol.setMaxConcurrentStreams(maxConcurrentStreams);
        http2Protocol.setHttp11Protocol((AbstractHttp11Protocol<?>) connector.getProtocolHandler());
        connector.addUpgradeProtocol(http2Protocol);
    }


    @Override
    protected void configureAndStartWebApplication() throws LifecycleException {
        Tomcat tomcat = getTomcatInstance();

        Context ctxt = getProgrammaticRootContext();
        // Target of the HTTP/2 upgrade request
        Tomcat.addServlet(ctxt, "simple", new SimpleServlet());
        ctxt.addServletMappingDecoded("/simple", "simple");
        Tomcat.addServlet(ctxt, "nocontent", new NoContentServlet());
        ctxt.addServletMappingDecoded("/nocontent", "nocontent");
        Tomcat.addServlet(ctxt, "blockedwrite", new BlockedWriteServlet());
        ctxt.addServletMappingDecoded("/blockedwrite", "blockedwrite");
        Wrapper w = Tomcat.addServlet(ctxt, "asynctimeout", new AsyncTimeoutServlet());
        w.setAsyncSupported(true);
        ctxt.addServletMappingDecoded("/asynctimeout", "asynctimeout");

        tomcat.start();
    }


    private static class ReuseTrackingHttp2Protocol extends Http2Protocol {

        private volatile Request lastPopped;
        private final AtomicInteger lastPoppedPushCount = new AtomicInteger();

        @Override
        public String getHttpUpgradeName(boolean isSSLEnabled) {
            return "h2c";
        }

        @Override
        Request popRequestAndResponse() {
            Request requestAndResponse = super.popRequestAndResponse();
            lastPoppedPushCount.set(0);
            lastPopped = requestAndResponse;
            return requestAndResponse;
        }

        @Override
        void pushRequestAndResponse(Request requestAndResponse) {
            /*
             * Only count pushes that occur after the request and response were popped. The request and response
             * created for the h2c upgrade request are legitimately recycled by stream 1 and may then be popped by a
             * later stream.
             */
            if (requestAndResponse == lastPopped) {
                lastPoppedPushCount.incrementAndGet();
            }
            super.pushRequestAndResponse(requestAndResponse);
        }

        Request getLastPopped() {
            return lastPopped;
        }

        int getLastPoppedPushCount() {
            return lastPoppedPushCount.get();
        }
    }


    private static class BlockedWriteServlet extends HttpServlet {

        private static final long serialVersionUID = 1L;

        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
            // Write more than the response buffer so the application thread blocks in the write
            resp.setContentType("application/octet-stream");

            int count = 128 * 1024;
            resp.setContentLengthLong(count * 2L);

            OutputStream os = resp.getOutputStream();
            byte[] data = new byte[2];
            for (int i = 0; i < count; i++) {
                data[0] = (byte) (i & 0xFF);
                data[1] = (byte) ((i >> 8) & 0xFF);
                os.write(data);
            }
        }
    }


    private static class AsyncTimeoutServlet extends HttpServlet {

        private static final long serialVersionUID = 1L;

        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
            AsyncContext asyncContext = req.startAsync();
            asyncContext.setTimeout(1000);
            asyncContext.addListener(new TimeoutListener());
        }
    }


    private static class TimeoutListener implements AsyncListener {

        @Override
        public void onTimeout(AsyncEvent event) throws IOException {
            HttpServletResponse resp = (HttpServletResponse) event.getAsyncContext().getResponse();
            resp.setStatus(HttpServletResponse.SC_OK);
            resp.setContentType("text/plain");
            resp.setCharacterEncoding("UTF-8");
            resp.getWriter().print(TIMEOUT_BODY);
            event.getAsyncContext().complete();
        }

        @Override
        public void onStartAsync(AsyncEvent event) throws IOException {
            // NO-OP
        }

        @Override
        public void onError(AsyncEvent event) throws IOException {
            // NO-OP
        }

        @Override
        public void onComplete(AsyncEvent event) throws IOException {
            // NO-OP
        }
    }
}
