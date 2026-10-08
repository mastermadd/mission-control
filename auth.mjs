import {scryptSync,randomBytes,timingSafeEqual,createHash} from 'node:crypto';
export function passwordHash(password,salt=randomBytes(32).toString('hex')){return {salt,hash:scryptSync(password,salt,64).toString('hex')}}
export function verifyPassword(password,record){const hash=scryptSync(password,record.salt,64),expected=Buffer.from(record.hash,'hex');return expected.length===hash.length&&timingSafeEqual(hash,expected)}
const digest=s=>createHash('sha256').update(s).digest('hex');
export function createSession(db,now=Date.now()){const token=randomBytes(32).toString('hex');db.sql.prepare('DELETE FROM local_sessions WHERE expires<?').run(now);db.sql.prepare('INSERT INTO local_sessions VALUES (?,?)').run(digest(token),now+86400000);return token}
export function sessionToken(cookie=''){return cookie.split(';').map(s=>s.trim()).find(s=>s.startsWith('mission_session='))?.slice(16)||''}
export function authenticated(db,cookie,now=Date.now()){const token=sessionToken(cookie);if(!/^[a-f0-9]{64}$/.test(token))return false;return !!db.sql.prepare('SELECT hash FROM local_sessions WHERE hash=? AND expires>?').get(digest(token),now)}
export function revokeSession(db,cookie){db.sql.prepare('DELETE FROM local_sessions WHERE hash=?').run(digest(sessionToken(cookie)))}
export function cookie(token,origin){return 'mission_session='+token+'; Path=/; HttpOnly; SameSite=Strict; Max-Age='+(token?'86400':'0')+(origin.startsWith('https:')?'; Secure':'')}
