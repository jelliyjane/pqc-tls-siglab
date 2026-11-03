#ifndef CATS_MODEL_H
#define CATS_MODEL_H
#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Frozen no-chain, cap-2 checkpoint. No online fitting or fallback. */
struct cats_model {
    int loaded;
    char level[3], source_sha256[65];
    double mu[7], sd[7], active[7], theta[20][4];
};
static int cats_model_level(const char *level)
{
    if (!strcmp(level,"L1")) return 0;
    if (!strcmp(level,"L3")) return 1;
    if (!strcmp(level,"L5")) return 2;
    return -1;
}
static int cats_model_token(FILE *f, char *token)
{
    int c; size_t n=0;
    do { c=fgetc(f); } while (c==' ' || c=='\t' || c=='\n');
    if (c==EOF) return 0;
    do {
        if (c<33 || c>126 || n>=127) return 0;
        token[n++]=(char)c; c=fgetc(f);
    } while (c!=EOF && c!=' ' && c!='\t' && c!='\n');
    token[n]=0; return 1;
}
static int cats_model_number(FILE *f, double *out)
{
    char token[128], *end;
    if (!cats_model_token(f,token)) return 0;
    errno=0; *out=strtod(token,&end);
    return end!=token && !*end && !errno && isfinite(*out) && fabs(*out)<=1e6;
}
static int cats_model_load(const char *path, const char *level, struct cats_model *out)
{
    FILE *f=fopen(path,"rb"); char token[128]; int ok=0,c;
    memset(out,0,sizeof(*out));
    if (!f || cats_model_level(level)<0) { if(f) fclose(f); return 0; }
    if (!cats_model_token(f,token) || strcmp(token,"CATS-NOCHAIN-CAP2-1")) goto done;
    if (!cats_model_token(f,token) || strcmp(token,level)) goto done;
    memcpy(out->level,level,3);
    if (!cats_model_token(f,token) || strlen(token)!=64) goto done;
    for (int i=0;i<64;i++) if (!strchr("0123456789abcdef",token[i])) goto done;
    memcpy(out->source_sha256,token,65);
    for(int i=0;i<7;i++) if(!cats_model_number(f,&out->mu[i])) goto done;
    for(int i=0;i<7;i++) if(!cats_model_number(f,&out->sd[i]) || out->sd[i]<=0) goto done;
    for(int i=0;i<7;i++) if(!cats_model_number(f,&out->active[i]) ||
        (out->active[i]!=0 && out->active[i]!=1)) goto done;
    for(int i=0;i<20;i++) for(int j=0;j<4;j++)
        if(!cats_model_number(f,&out->theta[i][j])) goto done;
    if(!cats_model_token(f,token) || strcmp(token,"END")) goto done;
    while((c=fgetc(f))!=EOF) if(c!=' ' && c!='\t' && c!='\n') goto done;
    if(ferror(f)) goto done;
    out->loaded=ok=1;
done:
    fclose(f); return ok;
}
static int cats_model_score(const struct cats_model *m, const double input[7],
                            double cost[4], double weights[4], double *score)
{
    double z[7],phi[20]; int k=8;
    if(!m->loaded) return 0;
    for(int i=0;i<7;i++) if(!isfinite(input[i]) || input[i]<0) return 0;
    /* RTT ms, BW Mbps, loss fraction, window bytes, sign ms, chain verify ms, flight bytes. */
    if(input[1]<=0 || input[2]>1 || input[3]<=0 || input[6]<=0) return 0;
    phi[0]=1;
    for(int i=0;i<7;i++) {
        double value=i==2?input[i]:log1p(input[i]);
        z[i]=m->active[i]?fmax(-3.,fmin(3.,(value-m->mu[i])/m->sd[i])):0;
        phi[i+1]=z[i];
    }
    for(int i=0;i<4;i++) for(int j=4;j<7;j++) phi[k++]=z[i]*z[j];
    cost[0]=input[4]; cost[1]=8*input[6]/(1000*input[1]);
    cost[2]=fmax(0.,ceil(input[6]/input[3])-1)*input[0]; cost[3]=input[5];
    *score=0;
    for(int j=0;j<4;j++) {
        double v=0;
        for(int i=0;i<20;i++) v+=phi[i]*m->theta[i][j];
        weights[j]=v>=0?2/(1+exp(-v)):2*exp(v)/(1+exp(v));
        *score+=weights[j]*cost[j];
    }
    return isfinite(*score);
}
#endif
