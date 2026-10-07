#include <QImage>
#include <cstdio>
#include <cassert>
#include <freerdp/codec/progressive.h>
#include <freerdp/codec/color.h>
int main() {
 const int w=1920,h=1080;
 QImage src(w,h,QImage::Format_RGB32),dst(w,h,QImage::Format_RGB32);
 src.fill(qRgb(30,30,30)); dst.fill(qRgb(0,0,0));
 for(int y=200;y<800;++y)for(int x=900;x<1020;++x)src.setPixel(x,y,qRgb(240,0,0));
 auto enc=progressive_context_new(TRUE), dec=progressive_context_new(FALSE);
 assert(enc&&dec); assert(progressive_create_surface_context(enc,1,w,h)>=0);assert(progressive_create_surface_context(dec,1,w,h)>=0);
 REGION16 damage{},out{};region16_init(&damage);region16_init(&out);RECTANGLE_16 r{0,0,w,h};region16_union_rect(&damage,&damage,&r);
 BYTE* data=nullptr;UINT32 len=0;
 int c=progressive_compress(enc,src.constBits(),src.sizeInBytes(),PIXEL_FORMAT_BGRX32,w,h,src.bytesPerLine(),&damage,&data,&len);
 assert(c>=0&&len>0);
 int d=progressive_decompress(dec,data,len,dst.bits(),PIXEL_FORMAT_BGRX32,dst.bytesPerLine(),0,0,&out,1,0);
 printf("decode=%d encoded=%u\n",d,len);assert(d>=0);
 int left=w,right=0;
 for(int x=0;x<w;++x)if(qRed(dst.pixel(x,500))>150){left=std::min(left,x);right=std::max(right,x);}
 printf("Decoded marker x=%d..%d, expected 900..1019\n",left,right);assert(abs(left-900)<=2&&abs(right-1019)<=2);
 progressive_context_free(enc);progressive_context_free(dec);region16_uninit(&damage);region16_uninit(&out);
}
