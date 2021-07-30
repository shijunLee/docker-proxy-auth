package log

import (
	"os"
	"time"

	"github.com/caarlos0/env"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

var Logger *zap.Logger
var AtomLevel zap.AtomicLevel

type LogConfig struct {
	LogFile string `env:"DOCKER_PROXY_AUTH_LOG_PATH" envDefault:"./log/docker-auth-proxy.log"`
}

func init() {
	logConfig := &LogConfig{}
	err := env.Parse(logConfig)
	if err != nil {
		panic(err)
	}
	w := zapcore.AddSync(&lumberjack.Logger{
		Filename:   logConfig.LogFile,
		MaxSize:    50, // megabytes
		MaxBackups: 3,
		MaxAge:     7, // days
	})
	AtomLevel = zap.NewAtomicLevel()
	AtomLevel.SetLevel(zapcore.DebugLevel)
	encoder := zap.NewProductionEncoderConfig()
	encoder.EncodeTime = func(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
		enc.AppendString(t.Format("2006-01-02 15:04:05"))
	}
	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(encoder),
		zapcore.NewMultiWriteSyncer(zapcore.AddSync(os.Stdout), w),
		AtomLevel,
	)
	Logger = zap.New(core, zap.AddCaller(), zap.AddStacktrace(zap.ErrorLevel))
	Logger.Info("Initialize logger successful.")
}
