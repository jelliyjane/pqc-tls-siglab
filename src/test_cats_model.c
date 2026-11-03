#include "cats_model.h"
int main(int argc,char **argv)
{
    struct cats_model model;
    if(argc!=3 || !cats_model_load(argv[1],argv[2],&model)) return 2;
    double x[7],c[4],w[4],score;
    for(;;) {
        int n=scanf("%lf %lf %lf %lf %lf %lf %lf",&x[0],&x[1],&x[2],&x[3],&x[4],&x[5],&x[6]);
        if(n==EOF) return 0;
        if(n!=7 || !cats_model_score(&model,x,c,w,&score)) return 3;
        printf("%.17g %.17g %.17g %.17g %.17g\n",score,w[0],w[1],w[2],w[3]);
    }
}
