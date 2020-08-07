const _ = require('lodash');
const BaseServerlessPlugin = require('base-serverless-plugin');

const LOG_PREFFIX = '[ServerlessWafAssociation] -';
const USR_CONF = 'wafAssociation';

const API_GATEWAY_TYPE = 'AWS::ApiGateway::RestApi';
const CLOUD_FRONT_TYPE = 'AWS::CloudFront::Distribution';
const ANY_LOAD_BALANCER_TYPE = '::LoadBalancer';

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

    this.getGlobalWebAclArn = _.once(() =>
      this.findWafWebAclArn(
        this.cfg.globalWebAclTagName,
        this.cfg.globalWebAclTagValue,
        'CLOUDFRONT'
      )
    );

    this.getRegionalWebAclArn = _.once(() =>
      this.findWafWebAclArn(
        this.cfg.regionalWebAclTagName,
        this.cfg.regionalWebAclTagValue,
        'REGIONAL'
      )
    );
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
    this.cfg.regionalWebAclTagName = this.getConf(
      'regionalWebAclTagName',
      'name'
    );
    this.cfg.regionalWebAclTagValue = this.getConf(
      'regionalWebAclTagValue',
      'WebACLRegional'
    );

    this.cfg.globalWebAclTagName = this.getConf('globalWebAclTagName', 'name');
    this.cfg.globalWebAclTagValue = this.getConf(
      'globalWebAclTagValue',
      'WebACLCloudfront'
    );
  }

  /**
   * Inject Waf
   *
   */
  async injectWebAclAssociations() {
    const cf = this.getCompiledTemplate();

    if (cf.Resources) {
      const entries = _.clone(Object.entries(cf.Resources));
      for (let i = 0; i < entries.length; i += 1) {
        const [key, res] = entries[i];

        // user can specified resources to skip
        if (this.cfg.skipResources.indexOf(key) > -1) {
          this.log(`Skipping resource "${key}"`);
          // eslint-disable-next-line
          continue;
        }

        const newResAssocKey = `WafAssociation${key}`;
        if (res.Type === CLOUD_FRONT_TYPE) {
          // eslint-disable-next-line
          const webAclArn = await this.getGlobalWebAclArn();
          this.checkCloudFrontWebAclArn(webAclArn);
          _.set(res, 'Properties.DistributionConfig.WebACLId', webAclArn);
          this.log(`Setting waf firewall to "${key}" CloudFront resource.`);
        } else if (res.Type === API_GATEWAY_TYPE) {
          // eslint-disable-next-line
          const webAclArn = await this.getRegionalWebAclArn();
          this.checkRegionalWebAclArn(webAclArn);

          const apigwArn = this.getApiGatewayArn(key);
          const ref = { 'Fn::Sub': apigwArn };
          const assoc = ServerlessPlugin.createAssociation(webAclArn, ref);

          assoc.DependsOn = [key];
          cf.Resources[newResAssocKey] = assoc;
          this.log(`Setting waf firewall to "${key}" rest api resource.`);

          // LOAD BALANCER V1 and V2 MATCH
        } else if (res.Type.endsWith(ANY_LOAD_BALANCER_TYPE)) {
          // defaults reference returns an arn
          // eslint-disable-next-line
          const webAclArn = await this.getRegionalWebAclArn();
          this.checkRegionalWebAclArn(webAclArn);
          const albArn = { Ref: key };

          const assoc = ServerlessPlugin.createAssociation(webAclArn, albArn);
          assoc.DependsOn = [key];
          cf.Resources[newResAssocKey] = assoc;

          this.log(`Setting waf firewall to "${key}" load balancer resource.`);
        }
      }
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
   * @static
   * @param {string} webAclArn web acl arn
   * @param {string} resourceArn api gateway or alb arn
   * @returns {object} association object
   */
  static createAssociation(webAclArn, resourceArn) {
    if (_.isEmpty(webAclArn)) throw new Error('webAclArn is required');
    if (_.isEmpty(resourceArn)) throw new Error('resourceArn is required');

    return {
      Type: 'AWS::WAFv2::WebACLAssociation',
      Properties: {
        WebACLArn: webAclArn,
        ResourceArn: resourceArn,
      },
    };
  }

  /**
   * Find Waf WebACL by Name
   *
   * @param {string} tagName web acl tagName
   * @param {string} tagValue web acl tagValue
   * @param {string} scope='REGIONAL' REGIONAL Or CLOUDFRONT
   * @returns {string} web acl arn
   */
  async findWafWebAclArn(tagName, tagValue, scope = 'REGIONAL') {
    let resArn;
    let tags;
    let found;

    const resp = await this.aws.request('WAFV2', 'listWebACLs', {
      Scope: scope,
    });

    const acls = _.get(resp, 'WebACLs', []);
    for (let i = 0; i < acls.length; i += 1) {
      // eslint-disable-next-line
      tags = await this.findWafWebAclTags(acls[i].ARN);
      found = tags.find(
        ({ Key, Value }) => Key === tagName && Value === tagValue
      );

      if (found) {
        resArn = acls[i].ARN;
        break;
      }
    }

    return resArn;
  }

  /**
   * Find Tags for Web Acl Resources
   *
   * @param {string} webAclArn web acl arn
   * @returns {array} Tag List
   */
  async findWafWebAclTags(webAclArn) {
    const resp = await this.aws.request('WAFV2', 'listTagsForResource', {
      ResourceARN: webAclArn,
    });

    return _.get(resp, 'TagInfoForResource.TagList', []);
  }

  /**
   * Check value or throw friendly message exception
   *
   * @param {string} arn web acl arn
   */
  checkCloudFrontWebAclArn(arn) {
    if (_.isEmpty(arn)) {
      let err = '';
      err += `Waf Firewall - Web acl with tag value "${this.cfg.globalWebAclTagValue}" not found. \n`;
      err += `Please check in your aws account the waf web acl resource for CloudFront (global) \n`;
      throw new Error(err);
    }
  }

  /**
   * Check value or throw friendly message exception
   *
   * @param {string} arn web acl arn
   */
  checkRegionalWebAclArn(arn) {
    if (_.isEmpty(arn)) {
      let err = '';
      err += `Waf Firewall - Web acl with tag value "${this.cfg.regionalWebAclTagValue}" not found. \n`;
      err += `Please check in your aws account the waf web acl resource \n`;
      throw new Error(err);
    }
  }
}

module.exports = ServerlessPlugin;
