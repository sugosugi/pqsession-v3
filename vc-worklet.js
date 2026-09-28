// pqsession 语音通话 AudioWorklet（采集打包 / 播放抖动缓冲）。
// v3：由中继同源提供（/vc-worklet.js），不再经 blob: URL 装载 —— CSP 的 script-src 因此可以去掉 blob:。
// 这里只做 PCM 的搬运与缓冲，不接触任何密钥或密文；编码、加密都在主线程的棘轮里完成。
// 播放积压上限 0.6 秒（超出丢最旧，钳住延迟漂移），与页面里的 VC_BACKLOG_S 保持一致。
class VCCap extends AudioWorkletProcessor{
  constructor(){ super(); this.buf=new Float32Array(2048); this.n=0; }
  process(inputs, outputs){
    const ch = inputs[0] && inputs[0][0];
    if(ch){
      let i=0;
      while(i<ch.length){
        const m = Math.min(ch.length-i, this.buf.length-this.n);
        this.buf.set(ch.subarray(i,i+m), this.n); this.n+=m; i+=m;
        if(this.n===this.buf.length){ this.port.postMessage(this.buf.slice(0)); this.n=0; }
      }
    }
    return true; // 输出保持静音（外接 gain=0 仅为确保节点被渲染图拉取）
  }
}
registerProcessor('vc-cap', VCCap);
class VCPlay extends AudioWorkletProcessor{
  constructor(){
    super(); this.q=[]; this.off=0; this.total=0;
    this.cap = Math.floor(sampleRate * 0.6);
    this.port.onmessage = (e)=>{
      const a=e.data; this.q.push(a); this.total+=a.length;
      while((this.total - this.off) > this.cap && this.q.length > 1){
        const d=this.q.shift(); this.total-=d.length; this.off=0;   // 积压过深：丢最旧，钳住延迟
      }
    };
  }
  process(_, outputs){
    const o = outputs[0]; const out = o && o[0]; if(!out) return true;
    let i=0;
    while(i<out.length && this.q.length){
      const h=this.q[0], m=Math.min(out.length-i, h.length-this.off);
      out.set(h.subarray(this.off,this.off+m), i); i+=m; this.off+=m;
      if(this.off>=h.length){ this.total-=h.length; this.q.shift(); this.off=0; }
    }
    for(;i<out.length;i++) out[i]=0;          // 欠载：补零（短暂静音）
    for(let c=1;c<o.length;c++) o[c].set(out);
    return true;
  }
}
registerProcessor('vc-play', VCPlay);
