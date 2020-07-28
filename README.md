## Serverless dinamic waf association
[![serverless](http://public.serverless.com/badges/v3.svg)](http://www.serverless.com)
[![npm version](https://badge.fury.io/js/serverless-waf-association.svg)](https://badge.fury.io/js/serverless-waf-association)
[![npm downloads](https://img.shields.io/npm/dt/serverless-waf-association.svg?style=flat)](https://www.npmjs.com/package/serverless-waf-association)

This plugin associates automatically your waf with all serverless yml resources applied to CloudFront, ApiGateway and Application LoadBalancer

### Installation
```bash
npm i -E serverless-waf-association
```


### Usage
```yaml
plugins:
  - serverless-waf-association

custom:
  wafAssociation:           # optional
    skipResources:          # optional
      - MyRestApiToSkip
      - LoadBalancerToSkip
```
