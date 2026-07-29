import { createHash, randomUUID } from 'node:crypto';

export const ARTIFACT_LIMITS = Object.freeze({ maxTextBytes: 1024 * 1024, maxBlobBytes: 16 * 1024 * 1024, maxTotalBytes: 32 * 1024 * 1024, maxOutputBytes: 64 * 1024 * 1024 });

export const RUNTIME_ARTIFACT_SCRIPT = String.raw`
const fs=require('fs'),path=require('path'),crypto=require('crypto');
const [baseline,workspace,generation,maxText,maxBlob,maxTotal]=process.argv.slice(1);let total=0;
function hash(b){return crypto.createHash('sha256').update(b).digest('hex')}
function scan(root){const out=new Map(),decoder=new TextDecoder('utf-8',{fatal:true});function walk(dir,rel=''){for(const name of fs.readdirSync(dir).sort((a,b)=>Buffer.from(a).compare(Buffer.from(b)))){const p=rel?rel+'/'+name:name;if(p==='.git'||p==='.openchamber'||p==='.openchamber-runtime')continue;const full=path.join(dir,name),s=fs.lstatSync(full),mode=s.mode&4095;if(s.isDirectory()){out.set(p,{path:p,type:'directory',mode});walk(full,p)}else if(s.isSymbolicLink()){const target=fs.readlinkSync(full);out.set(p,{path:p,type:'symlink',mode,target,hash:hash(Buffer.from(target))})}else if(s.isFile()){if(s.size>Number(maxBlob))throw new Error('workspace file exceeds export limit: '+p);const content=fs.readFileSync(full);let binary=content.includes(0);if(!binary)try{decoder.decode(content)}catch{binary=true}out.set(p,{path:p,type:'file',mode,size:content.length,hash:hash(content),binary,content})}else throw new Error('unsupported workspace entry: '+p)}}walk(root);return out}
const old=scan(baseline),next=scan(workspace),deleted=[],added=[],blobs={};let files=[];
for(const [p,e]of old)if(!next.has(p))deleted.push(e);for(const [p,e]of next)if(!old.has(p))added.push(e);
function signature(e){return e.type+':'+(e.hash||'')}
const addBySig=new Map();for(const e of added){const k=signature(e),list=addBySig.get(k)||[];list.push(e);addBySig.set(k,list)}
const used=new Set();for(const before of deleted){const matches=before.type==='directory'?[]:addBySig.get(signature(before))||[];const after=matches.find(e=>!used.has(e.path));if(after){used.add(after.path);files.push(change('rename',before,after))}else files.push(change('delete',before,null))}
for(const after of added)if(!used.has(after.path))files.push(change('add',null,after));
for(const [p,before]of old){const after=next.get(p);if(!after)continue;if(before.type!==after.type||before.hash!==after.hash||before.mode!==after.mode)files.push(change(before.hash===after.hash&&before.type===after.type?'mode':'modify',before,after))}
const concrete=files.filter(f=>(f.old&&f.old.type!=='directory')||(f.next&&f.next.type!=='directory'));files=files.filter(f=>{const e=f.next||f.old;if(e.type!=='directory')return true;const p=f.newPath||f.oldPath;return!concrete.some(c=>{const q=f.kind==='delete'?c.oldPath:c.newPath;return q&&q.startsWith(p+'/')})});
function blob(e){if(!e||e.type!=='file')return null;if(!blobs[e.hash]){total+=e.content.length;if(total>Number(maxTotal))throw new Error('workspace export exceeds total limit');blobs[e.hash]={hash:e.hash,size:e.size,contentBase64:e.content.toString('base64')}}return e.hash}
function clean(e){if(!e)return null;const {content,...rest}=e;return rest}
function textLines(e){return e&&e.type==='file'&&!e.binary&&e.size<=Number(maxText)?e.content.toString('utf8').split('\n'):null}
function textHunks(before,after){const a=textLines(before),b=textLines(after);if(!a&&!b)return[];const oldLines=a||[],newLines=b||[];let prefix=0,suffix=0;while(prefix<oldLines.length&&prefix<newLines.length&&oldLines[prefix]===newLines[prefix])prefix++;while(suffix<oldLines.length-prefix&&suffix<newLines.length-prefix&&oldLines[oldLines.length-1-suffix]===newLines[newLines.length-1-suffix])suffix++;if(prefix===oldLines.length&&prefix===newLines.length)return[];const removed=oldLines.slice(prefix,oldLines.length-suffix),added=newLines.slice(prefix,newLines.length-suffix),contextHash=hash(Buffer.from(JSON.stringify({before:oldLines[prefix-1]||'',after:oldLines[oldLines.length-suffix]||''})));return[{id:hash(Buffer.from(prefix+'\0'+removed.join('\n')+'\0'+added.join('\n')+'\0'+contextHash)),oldStart:prefix+1,oldCount:removed.length,newStart:prefix+1,newCount:added.length,removed,added,contextHash}]}
function change(kind,before,after){const oldPath=before&&before.path,newPath=after&&after.path,id=hash(Buffer.from(kind+'\0'+(oldPath||'')+'\0'+(newPath||'')+'\0'+(before&&before.hash||'')+'\0'+(after&&after.hash||'')));const text=after&&after.type==='file'&&!after.binary&&after.size<=Number(maxText)?after.content.toString('utf8'):undefined;return{id,kind,oldPath,newPath,binary:Boolean((before&&before.binary)||(after&&after.binary)),oldMode:before&&before.mode,newMode:after&&after.mode,baselineHash:before&&before.hash,resultHash:after&&after.hash,baselineBlob:blob(before),resultBlob:blob(after),symlinkTarget:after&&after.target,text,textHunks:textHunks(before,after),old:clean(before),next:clean(after)}}
process.stdout.write(JSON.stringify({version:1,baselineGeneration:generation,files:files.sort((a,b)=>(a.newPath||a.oldPath).localeCompare(b.newPath||b.oldPath)),blobs:Object.values(blobs),totalBytes:total}));
`;

export function finalizeArtifact(snapshot, metadata, targetDirectory, ttlMs = 60 * 60_000) {
  if (!snapshot || snapshot.version !== 1 || !Array.isArray(snapshot.files) || !Array.isArray(snapshot.blobs)) throw new TypeError('Invalid provider export snapshot');
  const createdAt = new Date();
  const artifact = {
    version: 1,
    id: randomUUID(),
    controlPlaneWorkspaceID: metadata.controlPlaneWorkspaceID,
    providerResourceID: metadata.providerResourceID,
    projectID: metadata.projectID,
    provider: metadata.provider,
    baselineGeneration: snapshot.baselineGeneration,
    targetDirectory,
    createdAt: createdAt.toISOString(),
    expiresAt: new Date(createdAt.getTime() + ttlMs).toISOString(),
    files: snapshot.files,
    blobs: snapshot.blobs,
  };
  artifact.integrityHash = createHash('sha256').update(JSON.stringify(artifact)).digest('hex');
  return artifact;
}
