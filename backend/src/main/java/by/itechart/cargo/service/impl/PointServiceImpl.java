package by.itechart.cargo.service.impl;

import by.itechart.cargo.dto.model_dto.waybill.UpdatePointsRequest;
import by.itechart.cargo.dto.notification.notification_data.PointNotificationData;
import by.itechart.cargo.exception.NotFoundException;
import by.itechart.cargo.model.Point;
import by.itechart.cargo.repository.PointRepository;
import by.itechart.cargo.service.PointService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import javax.transaction.Transactional;
import java.time.LocalDateTime;

import static by.itechart.cargo.service.util.MessageConstant.POINT_NOT_FOUND_MESSAGE;

@Service
@Transactional
@Slf4j
public class PointServiceImpl implements PointService {

    private final PointRepository pointRepository;

    @Autowired
    public PointServiceImpl(PointRepository pointRepository) {
        this.pointRepository = pointRepository;
    }

    @Override
    public Point findById(long id) throws NotFoundException {
        return pointRepository.findById(id).orElseThrow(() ->
                new NotFoundException(POINT_NOT_FOUND_MESSAGE));
    }

    @Override
    public void updatePoint(UpdatePointsRequest request) throws NotFoundException {
        final Point point = request.toPoint();
        Point foundPoint = pointRepository.findById(point.getId()).orElseThrow(() ->
                new NotFoundException(POINT_NOT_FOUND_MESSAGE));
        foundPoint.setPassageDate(LocalDateTime.now());
        foundPoint.setPassed(true);
        Point pointDb = pointRepository.save(foundPoint);
        log.info("Point has been passed {}", pointDb);
    }

    @Override
    public PointNotificationData findPointNotificationData(Long id) throws NotFoundException {
        Point point = pointRepository.findById(id).orElseThrow(() ->
                new NotFoundException(POINT_NOT_FOUND_MESSAGE));
        return PointNotificationData.fromPoint(point);

    }

}
