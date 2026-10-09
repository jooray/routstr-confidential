import { KEY_UPDATE_TYPE_MAP } from './constants.ts';
export declare function packKeyUpdateRecord(type: keyof typeof KEY_UPDATE_TYPE_MAP): Uint8Array<ArrayBufferLike>;
