package gov.usgs.wma.mlrlegacy;

import java.math.BigInteger;
import java.util.List;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.util.NumberUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/monitoringLocations")
public class Controller {

	@Autowired
	public MonitoringLocationDao mLDao;

	@GetMapping()
	public List<MonitoringLocation> getMonitoringLocations() {
		return mLDao.getByMap(null);
	}

	@GetMapping("/{id}")
	public MonitoringLocation getMonitoringLocation(@PathVariable("id") String id, HttpServletResponse response) {
		MonitoringLocation ml = mLDao.getById(NumberUtils.parseNumber(id, BigInteger.class));
		if (null == ml) {
			response.setStatus(HttpStatus.NOT_FOUND.value());
		}
		return ml;
	}

	@PostMapping()
	public MonitoringLocation createMonitoringLocation(@RequestBody MonitoringLocation ml, HttpServletResponse response) {
		ml.setCreatedBy("TEMP");
		ml.setUpdatedBy("TEMP");
		BigInteger newId = mLDao.create(ml);

		response.setStatus(HttpStatus.CREATED.value());
		return mLDao.getById(newId);
	}

	@PutMapping("/{id}")
	public MonitoringLocation updateMonitoringLocation(@PathVariable("id") String id, @RequestBody MonitoringLocation ml,
			HttpServletResponse response) {
		BigInteger idInt = NumberUtils.parseNumber(id, BigInteger.class);

		if (null == mLDao.getById(idInt)) {
			response.setStatus(HttpStatus.NOT_FOUND.value());
		}
		else {
			ml.setId(idInt);
			ml.setUpdatedBy("TEMP");
			mLDao.update(ml);
		}
		return mLDao.getById(idInt);
	}

}
