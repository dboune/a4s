"use strict";
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result["default"] = mod;
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
const core = __importStar(require("./core"));
exports.core = core;
const http = __importStar(require("./http"));
exports.http = http;
const s3 = __importStar(require("./s3"));
exports.s3 = s3;
const util = __importStar(require("./util"));
exports.util = util;
var request_1 = require("./util/request");
exports.toURL = request_1.toURL;
exports.toRequestOptions = request_1.toRequestOptions;
var http_1 = require("./http");
exports.signRequest = http_1.signRequest;
//# sourceMappingURL=index.js.map