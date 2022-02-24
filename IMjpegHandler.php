<?php

interface IMjpegHandler
{
    function OnFrameArrived($boundary, $frameId, $framePart);
    function OnFramePartArrived($boundary, $frameId, $framePart);
    function OnConnectionError($errCode, $errMsg, $isHttpError);
    function OnHeaderArrived($header);
}