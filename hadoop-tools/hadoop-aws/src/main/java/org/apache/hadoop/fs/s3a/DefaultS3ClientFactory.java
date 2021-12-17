/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.hadoop.fs.s3a;

import com.amazonaws.ClientConfiguration;
import com.amazonaws.Protocol;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.regions.RegionUtils;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3Builder;
import com.amazonaws.services.s3.AmazonS3Client;
import com.amazonaws.services.s3.AmazonS3EncryptionClientV2Builder;
import com.amazonaws.services.s3.S3ClientOptions;
import com.amazonaws.services.s3.internal.ServiceUtils;
import com.amazonaws.services.s3.model.CryptoConfigurationV2;
import com.amazonaws.services.s3.model.CryptoMode;
import com.amazonaws.services.s3.model.CryptoRangeGetMode;
import com.amazonaws.services.s3.model.EncryptionMaterialsProvider;
import com.amazonaws.services.s3.model.KMSEncryptionMaterialsProvider;
import com.amazonaws.util.AwsHostNameUtils;
import com.amazonaws.util.RuntimeHttpUtils;
import com.google.common.base.Preconditions;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.conf.Configured;
import org.apache.hadoop.util.VersionInfo;
import org.slf4j.Logger;

import java.io.IOException;
import java.net.URI;

import org.apache.commons.lang3.StringUtils;
import static org.apache.hadoop.fs.s3a.Constants.*;
import static org.apache.hadoop.fs.s3a.S3AUtils.createAWSCredentialProviderSet;
import static org.apache.hadoop.fs.s3a.S3AUtils.intOption;

/**
 * The default factory implementation, which calls the AWS SDK to configure
 * and create an {@link AmazonS3Client} that communicates with the S3 service.
 */
public class DefaultS3ClientFactory extends Configured implements
    S3ClientFactory {

  private static final String S3_SERVICE_NAME = "s3";

  protected static final Logger LOG = S3AFileSystem.LOG;

  /**
   * Warning message printed when the SDK Region chain is in use.
   */
  private static final String SDK_REGION_CHAIN_IN_USE =
      "S3A filesystem client is using"
          + " the SDK region resolution chain.";

  @Override
  public AmazonS3 createS3Client(URI name) throws IOException {
    Configuration conf = getConf();
    AWSCredentialsProvider credentials =
        createAWSCredentialProviderSet(name, conf);
    final ClientConfiguration awsConf = createAwsConf(getConf());


    /**
     * The "createAmazonS3Client()" function defined below configures: the endpoint and the path
     * access style parameters after the s3 client has been instantiatied. In the ClientV2 path
     * (i.e. FTX) we provide this parameters as part of the "S3ClientCreationParameters"
     */
    if (S3AEncryptionMethods.getMethod(S3AUtils.
      lookupPassword(conf, SERVER_SIDE_ENCRYPTION_ALGORITHM, null))
      .equals(S3AEncryptionMethods.CSE_FTX)) { // Fortanix branch
        S3ClientFactory.S3ClientCreationParameters parameters = null;
        parameters = new S3ClientFactory.S3ClientCreationParameters()
            .withCredentialSet(credentials)
            .withEndpoint(conf.getTrimmed(ENDPOINT, DEFAULT_ENDPOINT))
            .withPathStyleAccess(conf.getBoolean(PATH_STYLE_ACCESS, false));

        return buildAmazonS3EncryptionClient(
          awsConf,
          parameters);
    } else {
     AmazonS3 s3 = newAmazonS3Client(credentials, awsConf);
     return createAmazonS3Client(s3, conf, credentials, awsConf);
    }
  }

  /**
   * Create an {@link AmazonS3} client of type
   * {@link AmazonS3EncryptionV2} if CSE is enabled.
   *
   * @param awsConf    AWS configuration.
   * @param parameters parameters.
   *
   * @return new AmazonS3 client.
   * @throws IOException if lookupPassword() has any problem.
   */
  protected AmazonS3 buildAmazonS3EncryptionClient(
      final ClientConfiguration awsConf,
      final S3ClientCreationParameters parameters) throws IOException {

    AmazonS3 client;
    AmazonS3EncryptionClientV2Builder builder =
        new AmazonS3EncryptionClientV2Builder();
    Configuration conf = getConf();

    // CSE-FTX Method
    // Should we have a new config entry for CLIENT_SIDE_ENCRYPTION_KEY?
    String kmsKeyId = S3AUtils.lookupPassword(conf,
        SERVER_SIDE_ENCRYPTION_KEY, null);
    // Check if kmsKeyID is not null
    Preconditions.checkArgument(kmsKeyId != null, "CSE-KMS method "
        + "requires KMS key ID. Use " + SERVER_SIDE_ENCRYPTION_KEY
        + " property to set it. ");

    /* Original PR HADOOP-13887
    EncryptionMaterialsProvider materialsProvider =
        new KMSEncryptionMaterialsProvider(kmsKeyId);
    builder.withEncryptionMaterialsProvider(materialsProvider);
    */

    // TODO: For now we should pass the Ftx key name
    // Ideally we should use Ftx key Id during READ/DECRYPT and key name during WRITE/PUT
    // TODO: remove the hardcoded RSA param and use a config
    FortanixJCEProvider ftxJCEKeyChain = new FortanixJCEProvider("AES", kmsKeyId);
    builder.withEncryptionMaterialsProvider(ftxJCEKeyChain);

    //Configure basic params of a S3 builder.
    configureBasicParams(builder, awsConf, parameters);

    // Configuring endpoint.
    AmazonS3EncryptionClientV2Builder.EndpointConfiguration epr
        = createEndpointConfiguration(parameters.getEndpoint(),
        awsConf, getConf().getTrimmed(AWS_REGION));
    configureEndpoint(builder, epr);

    // Create cryptoConfig.
    CryptoConfigurationV2 cryptoConfigurationV2 =
        new CryptoConfigurationV2(CryptoMode.AuthenticatedEncryption)
            .withRangeGetMode(CryptoRangeGetMode.ALL);
    if (epr != null) {
      cryptoConfigurationV2
          .withAwsKmsRegion(RegionUtils.getRegion(epr.getSigningRegion()));
      LOG.debug("KMS region used: {}", cryptoConfigurationV2.getAwsKmsRegion());
    }

    // Added for Ftx
    cryptoConfigurationV2
      .withAlwaysUseCryptoProvider(false)
      .withCryptoMode(CryptoMode.AuthenticatedEncryption);

    cryptoConfigurationV2.withCryptoProvider(ftxJCEKeyChain.getProviderInstance()); // skip this to use default crypto provider (SunJCE/BC)

    builder.withCryptoConfiguration(cryptoConfigurationV2);
    client = builder.build();

    return client;
  }

  /**
   * A method to configure basic AmazonS3Builder parameters.
   *
   * @param builder    Instance of AmazonS3Builder used.
   * @param awsConf    ClientConfiguration used.
   * @param parameters Parameters used to set in the builder.
   */
  private void configureBasicParams(AmazonS3Builder builder,
      ClientConfiguration awsConf, S3ClientCreationParameters parameters) {
    builder.withCredentials(parameters.getCredentialSet());
    builder.withClientConfiguration(awsConf);
    builder.withPathStyleAccessEnabled(parameters.isPathStyleAccess());

    /**
     * TODO: Original code left below for reference only. This version of hadoop-aws doesn't
     * contain metrics, request handlers, nor monitoring.
     *
    if (parameters.getMetrics() != null) {
      builder.withMetricsCollector(
          new AwsStatisticsCollector(parameters.getMetrics()));
    }
    if (parameters.getRequestHandlers() != null) {
      builder.withRequestHandlers(
          parameters.getRequestHandlers().toArray(new RequestHandler2[0]));
    }
    if (parameters.getMonitoringListener() != null) {
      builder.withMonitoringListener(parameters.getMonitoringListener());
    }
    */
  }

  /**
   * Given an endpoint string, return an endpoint config, or null, if none
   * is needed.
   * <p>
   * This is a pretty painful piece of code. It is trying to replicate
   * what AwsClient.setEndpoint() does, because you can't
   * call that setter on an AwsClient constructed via
   * the builder, and you can't pass a metrics collector
   * down except through the builder.
   * <p>
   * Note also that AWS signing is a mystery which nobody fully
   * understands, especially given all problems surface in a
   * "400 bad request" response, which, like all security systems,
   * provides minimal diagnostics out of fear of leaking
   * secrets.
   *
   * @param endpoint possibly null endpoint.
   * @param awsConf config to build the URI from.
   * @param awsRegion AWS S3 Region if the corresponding config is set.
   * @return a configuration for the S3 client builder.
   */
  //@VisibleForTesting
  public static AwsClientBuilder.EndpointConfiguration
      createEndpointConfiguration(
      final String endpoint, final ClientConfiguration awsConf,
      String awsRegion) {
    LOG.debug("Creating endpoint configuration for \"{}\"", endpoint);
    if (endpoint == null || endpoint.isEmpty()) {
      // the default endpoint...we should be using null at this point.
      LOG.debug("Using default endpoint -no need to generate a configuration");
      return null;
    }

    final URI epr = RuntimeHttpUtils.toUri(endpoint, awsConf);
    LOG.debug("Endpoint URI = {}", epr);
    String region = awsRegion;
    if (StringUtils.isBlank(region)) {
      if (!ServiceUtils.isS3USStandardEndpoint(endpoint)) {
        LOG.debug("Endpoint {} is not the default; parsing", epr);
        region = AwsHostNameUtils.parseRegion(
            epr.getHost(),
            S3_SERVICE_NAME);
      } else {
        // US-east, set region == null.
        LOG.debug("Endpoint {} is the standard one; declare region as null",
            epr);
        region = null;
      }
    }
    LOG.debug("Region for endpoint {}, URI {} is determined as {}",
        endpoint, epr, region);
    return new AwsClientBuilder.EndpointConfiguration(endpoint, region);
  }

   /**
   * A method to configure endpoint and Region for an AmazonS3Builder.
   *
   * @param builder Instance of AmazonS3Builder used.
   * @param epr     EndpointConfiguration used to set in builder.
   */
  private void configureEndpoint(
      AmazonS3Builder builder,
      AmazonS3Builder.EndpointConfiguration epr) {
    if (epr != null) {
      // an endpoint binding was constructed: use it.
      builder.withEndpointConfiguration(epr);
    } else {
      // no idea what the endpoint is, so tell the SDK
      // to work it out at the cost of an extra HEAD request
      builder.withForceGlobalBucketAccessEnabled(true);
      // HADOOP-17771 force set the region so the build process doesn't halt.
      String region = getConf().getTrimmed(AWS_REGION, AWS_S3_CENTRAL_REGION);
      LOG.debug("fs.s3a.endpoint.region=\"{}\"", region);
      if (!region.isEmpty()) {
        // there's either an explicit region or we have fallen back
        // to the central one.
        LOG.debug("Using default endpoint; setting region to {}", region);
        builder.setRegion(region);
      } else {
        // no region.
        // allow this if people really want it; it is OK to rely on this
        // when deployed in EC2.
        // WARN_OF_DEFAULT_REGION_CHAIN.warn(SDK_REGION_CHAIN_IN_USE);
        LOG.debug(SDK_REGION_CHAIN_IN_USE);
      }
    }
  }

  /**
   * Create a new {@link ClientConfiguration}.
   * @param conf The Hadoop configuration
   * @return new AWS client configuration
   */
  public static ClientConfiguration createAwsConf(Configuration conf) {
    final ClientConfiguration awsConf = new ClientConfiguration();
    initConnectionSettings(conf, awsConf);
    initProxySupport(conf, awsConf);
    initUserAgent(conf, awsConf);
    return awsConf;
  }

  /**
   * Wrapper around constructor for {@link AmazonS3} client.  Override this to
   * provide an extended version of the client
   * @param credentials credentials to use
   * @param awsConf  AWS configuration
   * @return  new AmazonS3 client
   */
  protected AmazonS3 newAmazonS3Client(
      AWSCredentialsProvider credentials, ClientConfiguration awsConf) {
    return new AmazonS3Client(credentials, awsConf);
  }

  /**
   * Initializes all AWS SDK settings related to connection management.
   *
   * @param conf Hadoop configuration
   * @param awsConf AWS SDK configuration
   */
  private static void initConnectionSettings(Configuration conf,
      ClientConfiguration awsConf) {
    awsConf.setMaxConnections(intOption(conf, MAXIMUM_CONNECTIONS,
        DEFAULT_MAXIMUM_CONNECTIONS, 1));
    boolean secureConnections = conf.getBoolean(SECURE_CONNECTIONS,
        DEFAULT_SECURE_CONNECTIONS);
    awsConf.setProtocol(secureConnections ?  Protocol.HTTPS : Protocol.HTTP);
    awsConf.setMaxErrorRetry(intOption(conf, MAX_ERROR_RETRIES,
        DEFAULT_MAX_ERROR_RETRIES, 0));
    awsConf.setConnectionTimeout(intOption(conf, ESTABLISH_TIMEOUT,
        DEFAULT_ESTABLISH_TIMEOUT, 0));
    awsConf.setSocketTimeout(intOption(conf, SOCKET_TIMEOUT,
        DEFAULT_SOCKET_TIMEOUT, 0));
    int sockSendBuffer = intOption(conf, SOCKET_SEND_BUFFER,
        DEFAULT_SOCKET_SEND_BUFFER, 2048);
    int sockRecvBuffer = intOption(conf, SOCKET_RECV_BUFFER,
        DEFAULT_SOCKET_RECV_BUFFER, 2048);
    awsConf.setSocketBufferSizeHints(sockSendBuffer, sockRecvBuffer);
    String signerOverride = conf.getTrimmed(SIGNING_ALGORITHM, "");
    if (!signerOverride.isEmpty()) {
      LOG.debug("Signer override = {}", signerOverride);
      awsConf.setSignerOverride(signerOverride);
    }
  }

  /**
   * Initializes AWS SDK proxy support if configured.
   *
   * @param conf Hadoop configuration
   * @param awsConf AWS SDK configuration
   * @throws IllegalArgumentException if misconfigured
   */
  private static void initProxySupport(Configuration conf,
      ClientConfiguration awsConf) throws IllegalArgumentException {
    String proxyHost = conf.getTrimmed(PROXY_HOST, "");
    int proxyPort = conf.getInt(PROXY_PORT, -1);
    if (!proxyHost.isEmpty()) {
      awsConf.setProxyHost(proxyHost);
      if (proxyPort >= 0) {
        awsConf.setProxyPort(proxyPort);
      } else {
        if (conf.getBoolean(SECURE_CONNECTIONS, DEFAULT_SECURE_CONNECTIONS)) {
          LOG.warn("Proxy host set without port. Using HTTPS default 443");
          awsConf.setProxyPort(443);
        } else {
          LOG.warn("Proxy host set without port. Using HTTP default 80");
          awsConf.setProxyPort(80);
        }
      }
      String proxyUsername = conf.getTrimmed(PROXY_USERNAME);
      String proxyPassword = conf.getTrimmed(PROXY_PASSWORD);
      if ((proxyUsername == null) != (proxyPassword == null)) {
        String msg = "Proxy error: " + PROXY_USERNAME + " or " +
            PROXY_PASSWORD + " set without the other.";
        LOG.error(msg);
        throw new IllegalArgumentException(msg);
      }
      awsConf.setProxyUsername(proxyUsername);
      awsConf.setProxyPassword(proxyPassword);
      awsConf.setProxyDomain(conf.getTrimmed(PROXY_DOMAIN));
      awsConf.setProxyWorkstation(conf.getTrimmed(PROXY_WORKSTATION));
      if (LOG.isDebugEnabled()) {
        LOG.debug("Using proxy server {}:{} as user {} with password {} on " +
                "domain {} as workstation {}", awsConf.getProxyHost(),
            awsConf.getProxyPort(),
            String.valueOf(awsConf.getProxyUsername()),
            awsConf.getProxyPassword(), awsConf.getProxyDomain(),
            awsConf.getProxyWorkstation());
      }
    } else if (proxyPort >= 0) {
      String msg =
          "Proxy error: " + PROXY_PORT + " set without " + PROXY_HOST;
      LOG.error(msg);
      throw new IllegalArgumentException(msg);
    }
  }

  /**
   * Initializes the User-Agent header to send in HTTP requests to the S3
   * back-end.  We always include the Hadoop version number.  The user also
   * may set an optional custom prefix to put in front of the Hadoop version
   * number.  The AWS SDK interally appends its own information, which seems
   * to include the AWS SDK version, OS and JVM version.
   *
   * @param conf Hadoop configuration
   * @param awsConf AWS SDK configuration
   */
  private static void initUserAgent(Configuration conf,
      ClientConfiguration awsConf) {
    String userAgent = "Hadoop " + VersionInfo.getVersion();
    String userAgentPrefix = conf.getTrimmed(USER_AGENT_PREFIX, "");
    if (!userAgentPrefix.isEmpty()) {
      userAgent = userAgentPrefix + ", " + userAgent;
    }
    LOG.debug("Using User-Agent: {}", userAgent);
    awsConf.setUserAgentPrefix(userAgent);
  }

  /**
   * Creates an {@link AmazonS3Client} from the established configuration.
   *
   * @param conf Hadoop configuration
   * @param credentials AWS credentials
   * @param awsConf AWS SDK configuration
   * @return S3 client
   * @throws IllegalArgumentException if misconfigured
   */
  private static AmazonS3 createAmazonS3Client(AmazonS3 s3, Configuration conf,
      AWSCredentialsProvider credentials, ClientConfiguration awsConf)
      throws IllegalArgumentException {
    String endPoint = conf.getTrimmed(ENDPOINT, "");
    if (!endPoint.isEmpty()) {
      try {
        s3.setEndpoint(endPoint);
      } catch (IllegalArgumentException e) {
        String msg = "Incorrect endpoint: "  + e.getMessage();
        LOG.error(msg);
        throw new IllegalArgumentException(msg, e);
      }
    }
    enablePathStyleAccessIfRequired(s3, conf);
    return s3;
  }

  /**
   * Enables path-style access to S3 buckets if configured.  By default, the
   * behavior is to use virtual hosted-style access with URIs of the form
   * http://bucketname.s3.amazonaws.com.  Enabling path-style access and a
   * region-specific endpoint switches the behavior to use URIs of the form
   * http://s3-eu-west-1.amazonaws.com/bucketname.
   *
   * @param s3 S3 client
   * @param conf Hadoop configuration
   */
  private static void enablePathStyleAccessIfRequired(AmazonS3 s3,
      Configuration conf) {
    final boolean pathStyleAccess = conf.getBoolean(PATH_STYLE_ACCESS, false);
    if (pathStyleAccess) {
      LOG.debug("Enabling path style access!");
      s3.setS3ClientOptions(S3ClientOptions.builder()
          .setPathStyleAccess(true)
          .build());
    }
  }
}
