const _ = require('lodash');
const BaseServerlessPlugin = require('base-serverless-plugin');

const LOG_PREFFIX = '[ServerlessWafAssociation] -';
const USR_CONF = 'wafAssociation';

class ServerlessPlugin extends BaseServerlessPlugin {
  /**
   * Default Constructor
   *
   * @param {object} serverless the serverless instance
   * @param {object} options command line arguments
   */
  constructor(serverless, options) {
    super(serverless, options, LOG_PREFFIX, USR_CONF);

    this.hooks = {
      'before:aws:package:finalize:saveServiceState': this.dispatchAction.bind(
        this,
        this.injectWebAclAssociations
      ),
    };
  }

  /**
   * Action Wrapper check plugin condition before perform action
   *
   * @param {function} funAction serverless plugin action
   */
  async dispatchAction(funAction, varResolver = undefined) {
    if (this.isPluginDisabled()) {
      this.log('warning: plugin is disabled');
      return '';
    }

    this.loadConfig();
    return funAction.call(this, varResolver);
  }

  /**
   * Load user config
   *
   */
  loadConfig() {
    this.cfg = {};
    // allows array or string inputs
    this.cfg.skipResources = [].concat(this.getConf('skipResources', []));
  }

  /**
   * Inject Waf
   *
   */
  async injectWebAclAssociations() {
    const webAclArn = await ServerlessPlugin.getDefaultWafArn();
    const cf = this.getCompiledTemplate();

    if (cf.Resources) {
      _.forEach(cf.Resources, (res, key) => {
        if (this.cfg.skipResources.indexOf(key) > -1) {
          this.log(`Skipping resource "${key}"`);
          return;
        }

        const newResAssocKey = `WafAssociation${key}`;
        // CLOUD FRONT
        if (res.Type === 'AWS::CloudFront::Distribution') {
          _.set(res, 'Properties.DistributionConfig.WebACLId', webAclArn);
          this.log(`Setting waf firewall to "${key}" CloudFront resource.`);

          // API GATEWAYS
        } else if (res.Type === 'AWS::ApiGateway::RestApi') {
          const apigwArn = this.getApiGatewayArn(key);
          const ref = { 'Fn::Sub': apigwArn };
          const assoc = ServerlessPlugin.createAssociation(webAclArn, ref);
          assoc.DependsOn = [key];
          cf.Resources[newResAssocKey] = assoc;

          this.log(`Setting waf firewall to "${key}" rest api resource.`);

          // LOAD BALANCER V1 and V2 MATCH
        } else if (res.Type.endsWith('::LoadBalancer')) {
          // defaults reference returns an arn
          const albArn = { Ref: key };
          const assoc = ServerlessPlugin.createAssociation(webAclArn, albArn);
          assoc.DependsOn = [key];
          cf.Resources[newResAssocKey] = assoc;

          this.log(`Setting waf firewall to "${key}" load balancer resource.`);
        }
      });
    }
  }

  /**
   * Get arn for api gateway rest api
   *
   * @param {string} restApiId rest api id
   * @returns {string} arn for rest api
   */
  getApiGatewayArn(restApiId) {
    const region = this.getRegion();
    const stage = this.getStage();

    return `arn:aws:apigateway:${region}::/restapis/\${${restApiId}}/stages/${stage}`;
  }

  /**
   * Create waf association
   *
   * @param {string} webAclArn web acl arn
   * @param {string} resourceArn api gateway or alb arn
   * @returns {object} association object
   */
  static createAssociation(webAclArn, resourceArn) {
    return {
      Type: 'AWS::WAFv2::WebACLAssociation',
      Properties: {
        WebACLArn: webAclArn,
        ResourceArn: resourceArn,
      },
    };
  }

  /**
   * Get WebAcl Arn
   *
   * @returns {string} arn webacl
   */
  static async getDefaultWafArn() {
    // get waf arn from cloud formation output key
    // or search webacl arn via aws-sdk tag
    return 'arn:aws:wafv2:us-east-1:123456789012:global/webacl/ExampleWebACL/473e64fd-f30b-4765-81a0-62ad96dd167a';
  }
}

module.exports = ServerlessPlugin;
