CREATE DEFINER=`samuel.foot`@`%` PROCEDURE `Export_New_Surveys`()
BEGIN
    SET @rowcount_Table1=(select count(*) from rar_tmp);
	  set @rowcount_Table2=(select count(*) from lime_survey_785728);

    if @rowcount_Table1=@rowcount_table2 then
		    select 'Both tables have identical data';
    else
		    SET @rowcount_Table1=@rowcount_Table1+1;

		    WHILE @rowcount_Table1 <= @rowcount_table2 DO

				    set @createColumns =(select GROUP_CONCAT(CONCAT(q.sid, 'X', q.gid, 'X', q.qid, ' TEXT')) FROM lime_questions as q);
            SET @qry=CONCAT('create table resp_tmp (', @createColumns ,');');
						PREPARE `stmt` FROM @`qry`;
            EXECUTE `stmt`;
            DEALLOCATE PREPARE `stmt`;

			      set @columnsQuestions =(select GROUP_CONCAT(CONCAT(q.sid, 'X', q.gid, 'X', q.qid)) FROM lime_questions as q);

            SET @qry=CONCAT('insert into resp_tmp select ', @columnsQuestions ,' from lime_survey_785728 where id = ', @rowcount_Table1 ,';');
            PREPARE `stmt` FROM @`qry`;
            EXECUTE `stmt`;
            DEALLOCATE PREPARE `stmt`;

            set @counterMAX = (SELECT count(CONCAT(q.sid, 'X', q.gid, 'X', q.qid)) as col FROM lime_questions AS q);
            set @counter=1;

            WHILE @counter <= @counterMAX DO
                SET @rownr=0;

                SET @qry=CONCAT('select col INTO @columname from (SELECT @rownr:=@rownr+1 AS rowNumber, CONCAT(q.sid, "X", q.gid, "X", q.qid) as col FROM lime_questions AS q ) as cols where rowNumber = ', @counter ,';');
                PREPARE `stmt` FROM @`qry`;
                EXECUTE `stmt`;
                DEALLOCATE PREPARE `stmt`;

                SET @qry=CONCAT
                (
                	'select IF(
                		', @columname, ' like "A%",
                		(
                			select answer
                			from lime_answers
                			where qid =
                				(
                					select qid
                					from
                						(
                							SELECT
                							CONCAT(q.sid, "X", q.gid, "X", q.qid) AS sgq,
                							q.qid as qid
                							FROM lime_questions AS q
                						) as t
                					where sgq = "' , @columname , '"
                				)
                			and code =
                			(
                				select ', @columname,'
                				from resp_tmp
                			)
                		),
                		(
                			select ', @columname,'
                			from resp_tmp
                		)
                ) as test
                into @answer
                from resp_tmp;');
                PREPARE `stmt` FROM @`qry`;
                EXECUTE `stmt`;
                DEALLOCATE PREPARE `stmt`;


                set @question=CONCAT('(SELECT q.question FROM lime_questions AS q where CONCAT(q.sid, "X", q.gid, "X", q.qid) = "', @columname, '")');
                SET @qry=CONCAT('select CONCAT(', @question ,',": ","', @result ,'") into @QandA;');
                PREPARE `stmt` FROM @`qry`;
                EXECUTE `stmt`;
                DEALLOCATE PREPARE `stmt`;

                SET SQL_SAFE_UPDATES = 0;

                SET @qry=CONCAT('update resp_tmp set ', @columname, ' = "', @QandA, '";');
                PREPARE `stmt` FROM @`qry`;
                EXECUTE `stmt`;
                DEALLOCATE PREPARE `stmt`;
    		        SET @counter=@counter+1;
            END WHILE;

            SET @qry=CONCAT('select * INTO OUTFILE "/var/lib/mysql-files/', @rowcount_Table1 ,'.csv" FIELDS TERMINATED BY "," from resp_tmp;');
            PREPARE `stmt` FROM @`qry`;
            EXECUTE `stmt`;
            DEALLOCATE PREPARE `stmt`;

            SET @rowcount_Table1=@rowcount_Table1+1;
						DROP TABLE resp_tmp;
		    END WHILE;

    TRUNCATE TABLE rar_tmp;
    INSERT INTO rar_tmp select * from lime_survey_785728;

	end if;
END
