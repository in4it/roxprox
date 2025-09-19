FROM alpine:3.22.1
ADD build/als /usr/local/bin/als
EXPOSE 9001

# create a non-root user to run the application
RUN apk add --no-cache shadow \
    && useradd -u 1000 -U -m appuser \
    && chown -R appuser:appuser /usr/local/bin/

# Switch to the non-root user
USER appuser

ENTRYPOINT ["/usr/local/bin/als"]
