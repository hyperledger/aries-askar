import {Buffer} from 'buffer';

const base64 = (str: string) => Buffer.from(str).toString('base64');
// base64url is not available in the buffer library
export const base64url = (str: string) =>
  base64(str).replace(/\+/g, '_').replace(/\//g, '-').replace(/[=]+$/g, '');
