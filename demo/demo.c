#include <stdio.h>
#include <stdlib.h>

struct stu {
	char name[32];
	char data[2048];
	int len;
};

void init(struct stu *p){
	for(int i=0;i<100;i++){
		sprintf(p[i].name,"name:%d",i);
		sprintf(p[i].data,"data");
		p[i].len=5;
	}
}

void save(FILE *fd,struct stu *p){
	for(int i=0;i<100;i++){
		fwrite(&p[i],sizeof(struct stu),1,fd);
	}
}

void load(FILE *fd,struct stu *p){
	for(int i=0;i<100;i++){
		fread(&p[i],sizeof(struct stu),1,fd);
	}
}

void show(struct stu *p){
	for(int i=0;i<100;i++){
		printf("name:%s\n",p[i].name);
		printf("data:%s\n",p[i].data);
		printf("len :%d\n",p[i].len);
	}
}

int main(){
	FILE *fd,*fd2;
	struct stu stu[100];
	struct stu stu2[100];
	fd=fopen("data.txt","wb");
	init(stu);
	save(fd,stu);
	fclose(fd);
	fd2=fopen("data.txt","rb");
	load(fd2,stu2);
	show(stu2);
	fclose(fd2);
	return 0;
}
