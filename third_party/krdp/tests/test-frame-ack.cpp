#include "FrameAcknowledgement.h"
#include <cassert>
int main() {
 bool paused=false; QSet<uint32_t> p{10,11};
 acknowledgeFrames(p,paused,11,0); assert(p.empty() && !paused);
 p={20,21}; acknowledgeFrames(p,paused,19,0); assert(p.size()==2);
 acknowledgeFrames(p,paused,0,UINT32_MAX); assert(p.empty() && paused);
 p={30,31}; acknowledgeFrames(p,paused,30,0); assert(!paused && p==QSet<uint32_t>{31});
 p={UINT32_MAX,0}; acknowledgeFrames(p,paused,0,0); assert(p.empty());
 p={0,1}; acknowledgeFrames(p,paused,UINT32_MAX,0); assert(p.size()==2);
}
