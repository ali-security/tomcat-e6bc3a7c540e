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
package org.apache.catalina.filters;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Calendar;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.StringTokenizer;
import java.util.TimeZone;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.junit.Assert;
import org.junit.Test;

import org.apache.catalina.Context;
import org.apache.catalina.authenticator.BasicAuthenticator;
import org.apache.catalina.filters.ExpiresFilter.Duration;
import org.apache.catalina.filters.ExpiresFilter.DurationUnit;
import org.apache.catalina.filters.ExpiresFilter.ExpiresConfiguration;
import org.apache.catalina.filters.ExpiresFilter.StartingPoint;
import org.apache.catalina.startup.TesterMapRealm;
import org.apache.catalina.startup.TesterServlet;
import org.apache.catalina.startup.Tomcat;
import org.apache.catalina.startup.TomcatBaseTest;
import org.apache.tomcat.util.buf.ByteChunk;
import org.apache.tomcat.util.buf.StringUtils;
import org.apache.tomcat.util.collections.CaseInsensitiveKeyMap;
import org.apache.tomcat.util.descriptor.web.FilterDef;
import org.apache.tomcat.util.descriptor.web.FilterMap;
import org.apache.tomcat.util.descriptor.web.LoginConfig;
import org.apache.tomcat.util.descriptor.web.SecurityCollection;
import org.apache.tomcat.util.descriptor.web.SecurityConstraint;
import org.apache.tomcat.util.http.FastHttpDateFormat;

public class TestExpiresFilter extends TomcatBaseTest {
    public static final String TEMP_DIR = System.getProperty("java.io.tmpdir");

    @Test
    public void testConfiguration() throws Exception {

        Tomcat tomcat = getTomcatInstance();
        Context root = tomcat.addContext("", TEMP_DIR);

        FilterDef filterDef = new FilterDef();
        filterDef.addInitParameter("ExpiresDefault", "access plus 1 month");
        filterDef.addInitParameter("ExpiresByType text/html", "access plus 1 month 15 days 2 hours");
        filterDef.addInitParameter("ExpiresByType image/gif", "modification plus 5 hours 3 minutes");
        filterDef.addInitParameter("ExpiresByType image/jpg", "A10000");
        filterDef.addInitParameter("ExpiresByType video/mpeg", "M20000");
        filterDef.addInitParameter("ExpiresExcludedResponseStatusCodes", "304, 503");

        ExpiresFilter expiresFilter = new ExpiresFilter();

        filterDef.setFilter(expiresFilter);
        filterDef.setFilterClass(ExpiresFilter.class.getName());
        filterDef.setFilterName(ExpiresFilter.class.getName());

        root.addFilterDef(filterDef);

        FilterMap filterMap = new FilterMap();
        filterMap.setFilterName(ExpiresFilter.class.getName());
        filterMap.addURLPattern("*");

        tomcat.start();
        try {
            // VERIFY EXCLUDED RESPONSE STATUS CODES
            int[] excludedResponseStatusCodes = expiresFilter.getExcludedResponseStatusCodesAsInts();
            Assert.assertEquals(2, excludedResponseStatusCodes.length);
            Assert.assertEquals(304, excludedResponseStatusCodes[0]);
            Assert.assertEquals(503, excludedResponseStatusCodes[1]);

            // VERIFY DEFAULT CONFIGURATION
            ExpiresConfiguration expiresConfigurationDefault = expiresFilter.getDefaultExpiresConfiguration();
            Assert.assertEquals(StartingPoint.ACCESS_TIME, expiresConfigurationDefault.getStartingPoint());
            Assert.assertEquals(1, expiresConfigurationDefault.getDurations().size());
            Assert.assertEquals(DurationUnit.MONTH, expiresConfigurationDefault.getDurations().get(0).getUnit());
            Assert.assertEquals(1, expiresConfigurationDefault.getDurations().get(0).getAmount());

            // VERIFY TEXT/HTML
            ExpiresConfiguration expiresConfigurationTextHtml =
                    expiresFilter.getExpiresConfigurationByContentType().get("text/html");
            Assert.assertEquals(StartingPoint.ACCESS_TIME, expiresConfigurationTextHtml.getStartingPoint());

            Assert.assertEquals(3, expiresConfigurationTextHtml.getDurations().size());

            Duration oneMonth = expiresConfigurationTextHtml.getDurations().get(0);
            Assert.assertEquals(DurationUnit.MONTH, oneMonth.getUnit());
            Assert.assertEquals(1, oneMonth.getAmount());

            Duration fifteenDays = expiresConfigurationTextHtml.getDurations().get(1);
            Assert.assertEquals(DurationUnit.DAY, fifteenDays.getUnit());
            Assert.assertEquals(15, fifteenDays.getAmount());

            Duration twoHours = expiresConfigurationTextHtml.getDurations().get(2);
            Assert.assertEquals(DurationUnit.HOUR, twoHours.getUnit());
            Assert.assertEquals(2, twoHours.getAmount());

            // VERIFY IMAGE/GIF
            ExpiresConfiguration expiresConfigurationImageGif =
                    expiresFilter.getExpiresConfigurationByContentType().get("image/gif");
            Assert.assertEquals(StartingPoint.LAST_MODIFICATION_TIME, expiresConfigurationImageGif.getStartingPoint());

            Assert.assertEquals(2, expiresConfigurationImageGif.getDurations().size());

            Duration fiveHours = expiresConfigurationImageGif.getDurations().get(0);
            Assert.assertEquals(DurationUnit.HOUR, fiveHours.getUnit());
            Assert.assertEquals(5, fiveHours.getAmount());

            Duration threeMinutes = expiresConfigurationImageGif.getDurations().get(1);
            Assert.assertEquals(DurationUnit.MINUTE, threeMinutes.getUnit());
            Assert.assertEquals(3, threeMinutes.getAmount());

            // VERIFY IMAGE/JPG
            ExpiresConfiguration expiresConfigurationImageJpg =
                    expiresFilter.getExpiresConfigurationByContentType().get("image/jpg");
            Assert.assertEquals(StartingPoint.ACCESS_TIME, expiresConfigurationImageJpg.getStartingPoint());

            Assert.assertEquals(1, expiresConfigurationImageJpg.getDurations().size());

            Duration tenThousandSeconds = expiresConfigurationImageJpg.getDurations().get(0);
            Assert.assertEquals(DurationUnit.SECOND, tenThousandSeconds.getUnit());
            Assert.assertEquals(10000, tenThousandSeconds.getAmount());

            // VERIFY VIDEO/MPEG
            ExpiresConfiguration expiresConfiguration =
                    expiresFilter.getExpiresConfigurationByContentType().get("video/mpeg");
            Assert.assertEquals(StartingPoint.LAST_MODIFICATION_TIME, expiresConfiguration.getStartingPoint());

            Assert.assertEquals(1, expiresConfiguration.getDurations().size());

            Duration twentyThousandSeconds = expiresConfiguration.getDurations().get(0);
            Assert.assertEquals(DurationUnit.SECOND, twentyThousandSeconds.getUnit());
            Assert.assertEquals(20000, twentyThousandSeconds.getAmount());
        } finally {
            tomcat.stop();
        }
    }

    /*
     * Test that a resource with empty content is also processed
     */
    @Test
    public void testEmptyContent() throws Exception {
        HttpServlet servlet = new HttpServlet() {
            private static final long serialVersionUID = 1L;

            @Override
            protected void service(HttpServletRequest request, HttpServletResponse response)
                    throws ServletException, IOException {
                response.setContentType("text/plain");
                // no content is written in the response
            }
        };

        validate(servlet, Integer.valueOf(7 * 60));
    }

    @Test
    public void testParseExpiresConfigurationCombinedDuration() {
        ExpiresFilter expiresFilter = new ExpiresFilter();
        ExpiresConfiguration actualConfiguration =
                expiresFilter.parseExpiresConfiguration("access plus 1 month 15 days 2 hours");

        Assert.assertEquals(StartingPoint.ACCESS_TIME, actualConfiguration.getStartingPoint());

        Assert.assertEquals(3, actualConfiguration.getDurations().size());

    }

    @Test
    public void testParseExpiresConfigurationMonoDuration() {
        ExpiresFilter expiresFilter = new ExpiresFilter();
        ExpiresConfiguration actualConfiguration = expiresFilter.parseExpiresConfiguration("access plus 2 hours");

        Assert.assertEquals(StartingPoint.ACCESS_TIME, actualConfiguration.getStartingPoint());

        Assert.assertEquals(1, actualConfiguration.getDurations().size());
        Assert.assertEquals(2, actualConfiguration.getDurations().get(0).getAmount());
        Assert.assertEquals(DurationUnit.HOUR, actualConfiguration.getDurations().get(0).getUnit());

    }

    @Test
    public void testSkipBecauseCacheControlMaxAgeIsDefined() throws Exception {
        HttpServlet servlet = new HttpServlet() {
            private static final long serialVersionUID = 1L;

            @Override
            protected void service(HttpServletRequest request, HttpServletResponse response)
                    throws ServletException, IOException {
                response.setContentType("text/xml; charset=utf-8");
                response.addHeader("Cache-Control", "private, max-age=232");
                response.getWriter().print("Hello world");
            }
        };

        validate(servlet, Integer.valueOf(232));
    }

    @Test
    public void testExcludedResponseStatusCode() throws Exception {
        HttpServlet servlet = new HttpServlet() {
            private static final long serialVersionUID = 1L;

            @Override
            protected void service(HttpServletRequest request, HttpServletResponse response)
                    throws ServletException, IOException {
                response.setStatus(HttpServletResponse.SC_NOT_MODIFIED);
                response.addHeader("ETag", "W/\"1934-1269208821000\"");
                response.addDateHeader("Date", System.currentTimeMillis());
            }
        };

        validate(servlet, null, null, HttpServletResponse.SC_NOT_MODIFIED);
    }

    @Test
    public void testNullContentType() throws Exception {
        HttpServlet servlet = new HttpServlet() {
            private static final long serialVersionUID = 1L;

            @Override
            protected void service(HttpServletRequest request, HttpServletResponse response)
                    throws ServletException, IOException {
                response.setContentType(null);
            }
        };

        validate(servlet, Integer.valueOf(1 * 60));
    }

    @Test
    public void testSkipBecauseExpiresIsDefined() throws Exception {
        HttpServlet servlet = new HttpServlet() {
            private static final long serialVersionUID = 1L;

            @Override
            protected void service(HttpServletRequest request, HttpServletResponse response)
                    throws ServletException, IOException {
                response.setContentType("text/xml; charset=utf-8");
                response.addDateHeader("Expires", System.currentTimeMillis());
                response.getWriter().print("Hello world");
            }
        };

        validate(servlet, null);
    }

    @Test
    public void testUseContentTypeExpiresConfiguration() throws Exception {
        HttpServlet servlet = new HttpServlet() {
            private static final long serialVersionUID = 1L;

            @Override
            protected void service(HttpServletRequest request, HttpServletResponse response)
                    throws ServletException, IOException {
                response.setContentType("text/xml; charset=utf-8");
                response.getWriter().print("Hello world");
            }
        };

        validate(servlet, Integer.valueOf(3 * 60));
    }

    @Test
    public void testUseContentTypeWithoutCharsetExpiresConfiguration() throws Exception {
        HttpServlet servlet = new HttpServlet() {
            private static final long serialVersionUID = 1L;

            @Override
            protected void service(HttpServletRequest request, HttpServletResponse response)
                    throws ServletException, IOException {
                response.setContentType("text/xml; charset=iso-8859-1");
                response.getWriter().print("Hello world");
            }
        };

        validate(servlet, Integer.valueOf(5 * 60));
    }

    @Test
    public void testUseDefaultConfiguration1() throws Exception {
        HttpServlet servlet = new HttpServlet() {
            private static final long serialVersionUID = 1L;

            @Override
            protected void service(HttpServletRequest request, HttpServletResponse response)
                    throws ServletException, IOException {
                response.setContentType("image/jpeg");
                response.getWriter().print("Hello world");
            }
        };

        validate(servlet, Integer.valueOf(1 * 60));
    }

    @Test
    public void testUseDefaultConfiguration2() throws Exception {
        HttpServlet servlet = new HttpServlet() {
            private static final long serialVersionUID = 1L;

            @Override
            protected void service(HttpServletRequest request, HttpServletResponse response)
                    throws ServletException, IOException {
                response.setContentType("image/jpeg");
                response.addHeader("Cache-Control", "private");

                response.getWriter().print("Hello world");
            }
        };

        validate(servlet, Integer.valueOf(1 * 60));
    }

    @Test
    public void testUseDefaultConfiguration3() throws Exception {
        HttpServlet servlet = new HttpServlet() {
            private static final long serialVersionUID = 1L;

            @Override
            protected void service(HttpServletRequest request, HttpServletResponse response)
                    throws ServletException, IOException {
                response.setContentType("image/jpeg");
                response.addHeader("Cache-Control", "no-store");

                response.getWriter().print("Hello world");
            }
        };

        validate(servlet, null);
    }

    @Test
    public void testUseMajorTypeExpiresConfiguration() throws Exception {
        HttpServlet servlet = new HttpServlet() {
            private static final long serialVersionUID = 1L;

            @Override
            protected void service(HttpServletRequest request, HttpServletResponse response)
                    throws ServletException, IOException {
                response.setContentType("text/json; charset=iso-8859-1");
                response.getWriter().print("Hello world");
            }
        };

        validate(servlet, Integer.valueOf(7 * 60));
    }

    protected void validate(HttpServlet servlet, Integer expectedMaxAgeInSeconds) throws Exception {
        validate(servlet, expectedMaxAgeInSeconds, null, HttpServletResponse.SC_OK);
    }

    protected void validate(HttpServlet servlet, Integer expectedMaxAgeInSeconds, Boolean expectedExpires,
            int expectedResponseStatusCode) throws Exception {

        // SETUP

        Tomcat tomcat = getTomcatInstance();
        Context root = tomcat.addContext("", TEMP_DIR);

        FilterDef filterDef = new FilterDef();
        filterDef.addInitParameter("ExpiresDefault", "access plus 1 minute");
        filterDef.addInitParameter("ExpiresByType text/xml;charset=utf-8", "access plus 3 minutes");
        filterDef.addInitParameter("ExpiresByType text/xml", "access plus 5 minutes");
        filterDef.addInitParameter("ExpiresByType text", "access plus 7 minutes");
        filterDef.addInitParameter("ExpiresExcludedResponseStatusCodes", "304, 503");

        filterDef.setFilterClass(ExpiresFilter.class.getName());
        filterDef.setFilterName(ExpiresFilter.class.getName());

        root.addFilterDef(filterDef);

        FilterMap filterMap = new FilterMap();
        filterMap.setFilterName(ExpiresFilter.class.getName());
        filterMap.addURLPattern("*");
        root.addFilterMap(filterMap);

        Tomcat.addServlet(root, servlet.getClass().getName(), servlet);
        root.addServletMapping("/test", servlet.getClass().getName());

        tomcat.start();

        try {
            Calendar.getInstance(TimeZone.getTimeZone("GMT"));
            long timeBeforeInMillis = System.currentTimeMillis();

            // TEST
            ByteChunk bc = new ByteChunk();
            Map<String,List<String>> responseHeaders = new HashMap<>();
            int rc = getUrl("http://localhost:" + getPort() + "/test", bc, responseHeaders);

            // VALIDATE
            Assert.assertEquals(expectedResponseStatusCode, rc);

            StringBuilder msg = new StringBuilder();
            for (Entry<String,List<String>> field : responseHeaders.entrySet()) {
                for (String value : field.getValue()) {
                    msg.append((field.getKey() == null ? "" : field.getKey() + ": ") + value + "\n");
                }
            }
            System.out.println(msg);

            Integer actualMaxAgeInSeconds;

            String cacheControlHeader = StringUtils.join(responseHeaders.get("Cache-Control"));

            if (cacheControlHeader == null) {
                actualMaxAgeInSeconds = null;
            } else {
                actualMaxAgeInSeconds = null;
                StringTokenizer cacheControlTokenizer = new StringTokenizer(cacheControlHeader, ",");
                while (cacheControlTokenizer.hasMoreTokens() && actualMaxAgeInSeconds == null) {
                    String cacheDirective = cacheControlTokenizer.nextToken();
                    StringTokenizer cacheDirectiveTokenizer = new StringTokenizer(cacheDirective, "=");
                    if (cacheDirectiveTokenizer.countTokens() == 2) {
                        String key = cacheDirectiveTokenizer.nextToken().trim();
                        String value = cacheDirectiveTokenizer.nextToken().trim();
                        if (key.equalsIgnoreCase("max-age")) {
                            actualMaxAgeInSeconds = Integer.valueOf(value);
                        }
                    }
                }
            }

            if (expectedMaxAgeInSeconds == null) {
                Assert.assertTrue(
                        "actualMaxAgeInSeconds [" + actualMaxAgeInSeconds +
                                "] should be null or 'no-store' should be set",
                        actualMaxAgeInSeconds == null ||
                                (cacheControlHeader != null && cacheControlHeader.contains("no-store")));
                return;
            }

            Assert.assertNotNull(actualMaxAgeInSeconds);

            if (expectedExpires != null) {
                if (expectedExpires.booleanValue()) {
                    // Expires is expected and should be greater than date
                    Assert.assertNotNull(responseHeaders.get("Expires"));
                    String expiresString = responseHeaders.get("Expires").get(0);
                    long expiresDate = FastHttpDateFormat.parseDate(expiresString);
                    Assert.assertTrue(
                            "Expires header value [" + expiresString + "] does not specify a date in the future",
                            expiresDate > System.currentTimeMillis());
                } else {
                    Assert.assertNull(responseHeaders.get("Expires"));
                }
            }

            String contentType = getSingleHeader("Content-Type", responseHeaders);

            int deltaInSeconds = Math.abs(actualMaxAgeInSeconds.intValue() - expectedMaxAgeInSeconds.intValue());
            Assert.assertTrue("actualMaxAgeInSeconds: " + actualMaxAgeInSeconds + ", expectedMaxAgeInSeconds: " +
                    expectedMaxAgeInSeconds + ", request time: " + timeBeforeInMillis + " for content type " +
                    contentType, deltaInSeconds < 3);

        } finally {
            tomcat.stop();
        }
    }

    @Test
    public void testIntsToCommaDelimitedString() {
        String actual = ExpiresFilter.intsToCommaDelimitedString(new int[] { 500, 503 });
        String expected = "500, 503";

        Assert.assertEquals(expected, actual);
    }


    /*
     * Tests Expires filter with: - per content type expires - no default - Default servlet returning 304s (without
     * content-type)
     */
    @Test
    public void testBug63909() throws Exception {

        Tomcat tomcat = getTomcatInstanceTestWebapp(false, false);
        Context ctxt = (Context) tomcat.getHost().findChild("/test");

        FilterDef filterDef = new FilterDef();
        filterDef.addInitParameter("ExpiresByType text/xml;charset=utf-8", "access plus 3 minutes");
        filterDef.addInitParameter("ExpiresByType text/xml", "access plus 5 minutes");
        filterDef.addInitParameter("ExpiresByType text", "access plus 7 minutes");
        filterDef.addInitParameter("ExpiresExcludedResponseStatusCodes", "");

        filterDef.setFilterClass(ExpiresFilter.class.getName());
        filterDef.setFilterName(ExpiresFilter.class.getName());

        ctxt.addFilterDef(filterDef);

        FilterMap filterMap = new FilterMap();
        filterMap.setFilterName(ExpiresFilter.class.getName());
        filterMap.addURLPattern("*");
        ctxt.addFilterMap(filterMap);

        tomcat.start();

        ByteChunk bc = new ByteChunk();
        Map<String,List<String>> requestHeaders = new CaseInsensitiveKeyMap<>();
        List<String> ifModifiedSinceValues = new ArrayList<>();
        ifModifiedSinceValues.add(FastHttpDateFormat.getCurrentDate());
        requestHeaders.put("If-Modified-Since", ifModifiedSinceValues);
        Map<String,List<String>> responseHeaders = new CaseInsensitiveKeyMap<>();

        int rc = getUrl("http://localhost:" + getPort() + "/test/bug6nnnn/bug69303.txt", bc, requestHeaders,
                responseHeaders);

        Assert.assertEquals(HttpServletResponse.SC_NOT_MODIFIED, rc);

        StringBuilder msg = new StringBuilder();
        for (Entry<String,List<String>> field : responseHeaders.entrySet()) {
            for (String value : field.getValue()) {
                msg.append((field.getKey() == null ? "" : field.getKey() + ": ") + value + "\n");
            }
        }
        System.out.println(msg);

        Integer actualMaxAgeInSeconds;

        String cacheControlHeader = getSingleHeader("Cache-Control", responseHeaders);

        if (cacheControlHeader == null) {
            actualMaxAgeInSeconds = null;
        } else {
            actualMaxAgeInSeconds = null;
            StringTokenizer cacheControlTokenizer = new StringTokenizer(cacheControlHeader, ",");
            while (cacheControlTokenizer.hasMoreTokens() && actualMaxAgeInSeconds == null) {
                String cacheDirective = cacheControlTokenizer.nextToken();
                StringTokenizer cacheDirectiveTokenizer = new StringTokenizer(cacheDirective, "=");
                if (cacheDirectiveTokenizer.countTokens() == 2) {
                    String key = cacheDirectiveTokenizer.nextToken().trim();
                    String value = cacheDirectiveTokenizer.nextToken().trim();
                    if (key.equalsIgnoreCase("max-age")) {
                        actualMaxAgeInSeconds = Integer.valueOf(value);
                    }
                }
            }
        }

        Assert.assertNotNull(actualMaxAgeInSeconds);
        Assert.assertTrue(Math.abs(actualMaxAgeInSeconds.intValue() - 420) < 3);
    }


    @Test
    public void testBug69439CacheControlDirectiveConflict() throws Exception {
        HttpServlet servlet = new HttpServlet() {
            private static final long serialVersionUID = 1L;

            @Override
            protected void service(HttpServletRequest request, HttpServletResponse response)
                    throws ServletException, IOException {
                response.setContentType("image/jpeg");
                response.addHeader("Cache-Control", "public");
                response.addHeader("Cache-Control", "no-store");
                response.addHeader("Cache-Control", "max-age=300");
                response.getWriter().print("Hello world");
            }
        };
        // rfc9111 - 4.2.1 - If directives conflict (e.g., both max-age and no-cache are present), the most restrictive
        // directive should be honored.
        // final effective Cache-Control: no-store
        // skip ExpiresFilter
        validate(servlet, null, Boolean.FALSE, HttpServletResponse.SC_OK);
    }


    @Test
    public void testBug69439CacheControlMaxAgePredefined() throws Exception {
        HttpServlet servlet = new HttpServlet() {
            private static final long serialVersionUID = 1L;

            @Override
            protected void service(HttpServletRequest request, HttpServletResponse response)
                    throws ServletException, IOException {
                response.setContentType("image/jpeg");
                response.addHeader("Cache-Control", "public");
                response.addHeader("Cache-Control", "max-age=600");
                response.getWriter().print("Hello world");
            }
        };
        // rfc9111 - 4.2.1 - If directives conflict (e.g., both max-age and no-cache are present), the most restrictive
        // directive should be honored.
        // final effective Cache-Control: public, max-age=600
        // skip ExpiresFilter
        validate(servlet, Integer.valueOf(600), Boolean.FALSE, HttpServletResponse.SC_OK);
    }


    @Test
    public void testBug69439CacheControlUndefined() throws Exception {
        HttpServlet servlet = new HttpServlet() {
            private static final long serialVersionUID = 1L;

            @Override
            protected void service(HttpServletRequest request, HttpServletResponse response)
                    throws ServletException, IOException {
                response.setContentType("image/jpeg");
                response.getWriter().print("Hello world");
            }
        };
        // rfc9111 - 4.2.1 - If directives conflict (e.g., both max-age and no-cache are present), the most restrictive
        // directive should be honored.
        // final effective Cache-Control: public, max-age=600
        // apply ExpiresFilter
        validate(servlet, Integer.valueOf(60), Boolean.TRUE, HttpServletResponse.SC_OK);
    }


    /*
     * Cache-Control set by a previous filter must be retained when the ExpiresFilter adds max-age.
     */
    @Test
    public void testCacheControlPrivateSetByPreviousFilter() throws Exception {
        Map<String,List<String>> responseHeaders = doTestCacheControlSetByPreviousFilter("private");

        List<String> directives = getCacheControlDirectives(responseHeaders);
        Assert.assertTrue(directives.toString(), directives.contains("private"));
        Integer maxAge = getMaxAge(directives);
        Assert.assertNotNull(directives.toString(), maxAge);
        Assert.assertTrue(directives.toString(), Math.abs(maxAge.intValue() - 60) < 3);
        Assert.assertNotNull(responseHeaders.get("Expires"));
    }


    /*
     * Cache-Control no-store set by a previous filter must be retained and must prevent the ExpiresFilter adding
     * caching headers.
     */
    @Test
    public void testCacheControlNoStoreSetByPreviousFilter() throws Exception {
        Map<String,List<String>> responseHeaders = doTestCacheControlSetByPreviousFilter("no-store");

        List<String> directives = getCacheControlDirectives(responseHeaders);
        Assert.assertTrue(directives.toString(), directives.contains("no-store"));
        Assert.assertNull(directives.toString(), getMaxAge(directives));
        Assert.assertNull(responseHeaders.get("Expires"));
    }


    /*
     * Cache-Control max-age set by a previous filter must be retained and must prevent the ExpiresFilter adding
     * caching headers.
     */
    @Test
    public void testCacheControlMaxAgeSetByPreviousFilter() throws Exception {
        Map<String,List<String>> responseHeaders = doTestCacheControlSetByPreviousFilter("max-age=600");

        List<String> directives = getCacheControlDirectives(responseHeaders);
        Assert.assertEquals(directives.toString(), Integer.valueOf(600), getMaxAge(directives));
        Assert.assertNull(responseHeaders.get("Expires"));
    }


    /*
     * Cache-Control set by a previous filter must be retained when the application adds further Cache-Control
     * headers and the ExpiresFilter adds max-age.
     */
    @Test
    public void testCacheControlSetByPreviousFilterAndApplication() throws Exception {
        HttpServlet servlet = new HttpServlet() {
            private static final long serialVersionUID = 1L;

            @Override
            protected void service(HttpServletRequest request, HttpServletResponse response)
                    throws ServletException, IOException {
                response.setContentType("image/jpeg");
                response.addHeader("Cache-Control", "no-transform");
                response.getWriter().print("Hello world");
            }
        };
        Map<String,List<String>> responseHeaders = doTestCacheControlSetByPreviousFilter("private", servlet);

        List<String> directives = getCacheControlDirectives(responseHeaders);
        Assert.assertTrue(directives.toString(), directives.contains("private"));
        Assert.assertTrue(directives.toString(), directives.contains("no-transform"));
        Assert.assertEquals(directives.toString(), 1, Collections.frequency(directives, "private"));
        Integer maxAge = getMaxAge(directives);
        Assert.assertNotNull(directives.toString(), maxAge);
        Assert.assertTrue(directives.toString(), Math.abs(maxAge.intValue() - 60) < 3);
    }


    /*
     * Cache-Control set by the authenticator for a protected resource must be retained when the ExpiresFilter adds
     * max-age.
     */
    @Test
    public void testCacheControlSetByAuthenticator() throws Exception {
        Tomcat tomcat = getTomcatInstance();
        Context ctxt = tomcat.addContext("", TEMP_DIR);

        Tomcat.addServlet(ctxt, "TesterServlet", new TesterServlet());
        ctxt.addServletMapping("/protected", "TesterServlet");
        SecurityCollection collection = new SecurityCollection();
        collection.addPattern("/protected");
        SecurityConstraint sc = new SecurityConstraint();
        sc.addAuthRole("role");
        sc.addCollection(collection);
        ctxt.addConstraint(sc);

        TesterMapRealm realm = new TesterMapRealm();
        realm.addUser("user", "pwd");
        realm.addUserRole("user", "role");
        ctxt.setRealm(realm);

        LoginConfig lc = new LoginConfig();
        lc.setAuthMethod(HttpServletRequest.BASIC_AUTH);
        ctxt.setLoginConfig(lc);
        ctxt.getPipeline().addValve(new BasicAuthenticator());

        addExpiresFilter(ctxt);

        tomcat.start();

        Map<String,List<String>> requestHeaders = new CaseInsensitiveKeyMap<>();
        List<String> authorization = new ArrayList<>();
        authorization.add(
                "Basic " + Base64.getEncoder().encodeToString("user:pwd".getBytes(StandardCharsets.ISO_8859_1)));
        requestHeaders.put("Authorization", authorization);
        Map<String,List<String>> responseHeaders = new CaseInsensitiveKeyMap<>();
        ByteChunk bc = new ByteChunk();

        int rc = getUrl("http://localhost:" + getPort() + "/protected", bc, requestHeaders, responseHeaders);

        Assert.assertEquals(HttpServletResponse.SC_OK, rc);
        Assert.assertEquals("OK", bc.toString());

        List<String> directives = getCacheControlDirectives(responseHeaders);
        Assert.assertTrue(directives.toString(), directives.contains("private"));
        Integer maxAge = getMaxAge(directives);
        Assert.assertNotNull(directives.toString(), maxAge);
        Assert.assertTrue(directives.toString(), Math.abs(maxAge.intValue() - 60) < 3);
    }


    private Map<String,List<String>> doTestCacheControlSetByPreviousFilter(String cacheControl) throws Exception {
        HttpServlet servlet = new HttpServlet() {
            private static final long serialVersionUID = 1L;

            @Override
            protected void service(HttpServletRequest request, HttpServletResponse response)
                    throws ServletException, IOException {
                response.setContentType("image/jpeg");
                response.getWriter().print("Hello world");
            }
        };
        return doTestCacheControlSetByPreviousFilter(cacheControl, servlet);
    }


    private Map<String,List<String>> doTestCacheControlSetByPreviousFilter(String cacheControl, HttpServlet servlet)
            throws Exception {
        Tomcat tomcat = getTomcatInstance();
        Context root = tomcat.addContext("", TEMP_DIR);

        // Filter that sets Cache-Control before the ExpiresFilter is called
        FilterDef cacheControlFilterDef = new FilterDef();
        cacheControlFilterDef.setFilter(new CacheControlFilter(cacheControl));
        cacheControlFilterDef.setFilterClass(CacheControlFilter.class.getName());
        cacheControlFilterDef.setFilterName(CacheControlFilter.class.getName());
        root.addFilterDef(cacheControlFilterDef);

        FilterMap cacheControlFilterMap = new FilterMap();
        cacheControlFilterMap.setFilterName(CacheControlFilter.class.getName());
        cacheControlFilterMap.addURLPattern("*");
        root.addFilterMap(cacheControlFilterMap);

        addExpiresFilter(root);

        Tomcat.addServlet(root, servlet.getClass().getName(), servlet);
        root.addServletMapping("/test", servlet.getClass().getName());

        tomcat.start();

        ByteChunk bc = new ByteChunk();
        Map<String,List<String>> responseHeaders = new CaseInsensitiveKeyMap<>();
        int rc = getUrl("http://localhost:" + getPort() + "/test", bc, responseHeaders);

        Assert.assertEquals(HttpServletResponse.SC_OK, rc);

        return responseHeaders;
    }


    private void addExpiresFilter(Context ctxt) {
        FilterDef filterDef = new FilterDef();
        filterDef.addInitParameter("ExpiresDefault", "access plus 1 minute");

        filterDef.setFilterClass(ExpiresFilter.class.getName());
        filterDef.setFilterName(ExpiresFilter.class.getName());

        ctxt.addFilterDef(filterDef);

        FilterMap filterMap = new FilterMap();
        filterMap.setFilterName(ExpiresFilter.class.getName());
        filterMap.addURLPattern("*");
        ctxt.addFilterMap(filterMap);
    }


    private static List<String> getCacheControlDirectives(Map<String,List<String>> responseHeaders) {
        List<String> directives = new ArrayList<>();
        List<String> cacheControlHeaders = responseHeaders.get("Cache-Control");
        if (cacheControlHeaders != null) {
            for (String cacheControlHeader : cacheControlHeaders) {
                StringTokenizer cacheControlTokenizer = new StringTokenizer(cacheControlHeader, ",");
                while (cacheControlTokenizer.hasMoreTokens()) {
                    directives.add(cacheControlTokenizer.nextToken().trim());
                }
            }
        }
        return directives;
    }


    private static Integer getMaxAge(List<String> directives) {
        for (String directive : directives) {
            StringTokenizer cacheDirectiveTokenizer = new StringTokenizer(directive, "=");
            if (cacheDirectiveTokenizer.countTokens() == 2) {
                String key = cacheDirectiveTokenizer.nextToken().trim();
                String value = cacheDirectiveTokenizer.nextToken().trim();
                if (key.equalsIgnoreCase("max-age")) {
                    return Integer.valueOf(value);
                }
            }
        }
        return null;
    }


    public static class CacheControlFilter implements Filter {

        private final String cacheControl;

        public CacheControlFilter(String cacheControl) {
            this.cacheControl = cacheControl;
        }

        @Override
        public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
                throws IOException, ServletException {
            ((HttpServletResponse) response).setHeader("Cache-Control", cacheControl);
            chain.doFilter(request, response);
        }
    }
}
