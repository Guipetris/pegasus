FROM gcr.io/oss-fuzz-base/base-builder-rust

COPY . $SRC/pegasus
WORKDIR $SRC/pegasus

COPY .clusterfuzzlite/build.sh $SRC/build.sh
