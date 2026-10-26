package com.capstone.vuln.file;

import java.nio.file.Path;

/**
 * PathTraversalValidator 입력 (ValidationContext.payload)
 * - resultType: FileController가 산출한 기존 result_type (FILE_RETURNED / NOT_FOUND / ERROR)
 * - requestedPath / baseDir: 업로드 디렉터리 밖 파일인지 판정하는 데 사용 (ERROR 시 requestedPath는 null 가능)
 * - 파일 내용 자체는 담지 않는다 (길이/텍스트·바이너리 추정만)
 */
public record PathTraversalInput(
        ResultType resultType,
        Path requestedPath,
        Path baseDir,
        long contentLength,
        String contentType) {

    public enum ResultType {
        FILE_RETURNED,
        NOT_FOUND,
        ERROR
    }

    public static PathTraversalInput fileReturned(Path requestedPath, Path baseDir,
                                                  long contentLength, String contentType) {
        return new PathTraversalInput(ResultType.FILE_RETURNED, requestedPath, baseDir, contentLength, contentType);
    }

    public static PathTraversalInput notFound(Path requestedPath, Path baseDir) {
        return new PathTraversalInput(ResultType.NOT_FOUND, requestedPath, baseDir, 0, null);
    }

    public static PathTraversalInput error(Path baseDir) {
        return new PathTraversalInput(ResultType.ERROR, null, baseDir, 0, null);
    }
}
